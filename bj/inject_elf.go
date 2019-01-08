package bj

import (
	"debug/elf"
	"log"
)

// ElfBinject - Inject shellcode into an ELF binary
func ElfBinject(sourceFile string, destFile string, shellcode string, config *BinjectConfig) error {

	//
	// BEGIN CODE CAVE DETECTION SECTION
	//

	if config.CodeCaveMode == true {
		log.Printf("Using Code Cave Method")
		caves, err := FindCaves(sourceFile)
		if err != nil {
			return err
		}

		elfFile, err := elf.Open(sourceFile)
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

	return nil
}
