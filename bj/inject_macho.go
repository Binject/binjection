package bj

import (
	"debug/macho"
	"log"
)

// MachoBinject - Inject shellcode into an Mach-O binary
func MachoBinject(sourceFile string, destFile string, shellcode string, config *BinjectConfig) error {
	//
	// BEGIN CODE CAVE DETECTION SECTION
	//

	machoFile, err := macho.Open(sourceFile)
	if err != nil {
		return err
	}
	for _, section := range machoFile.Sections {
		if section.SectionHeader.Seg == "__TEXT" && section.Name == "__text" {
			caveOffset := 0x20 /* magic value */ + machoFile.FileHeader.Cmdsz
			log.Printf("Code Cave Size: %x - %x = %x\n", section.Offset, caveOffset, section.Offset-caveOffset)
		}
	}

	//
	// END CODE CAVE DETECTION SECTION
	//

	return nil
}
