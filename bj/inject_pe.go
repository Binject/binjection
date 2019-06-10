package bj

import (
	"bytes"
	"debug/pe"
	"log"
)

// PeBinject - Inject shellcode into an PE binary
func PeBinject(sourceBytes []byte, shellcodeBytes []byte, config *BinjectConfig) ([]byte, error) {
	//
	// BEGIN CODE CAVE DETECTION SECTION
	//
	if config.CodeCaveMode == true {
		log.Printf("Using Code Cave Method")
		caves, err := FindCaves(sourceBytes)
		if err != nil {
			return nil, err
		}
		peFile, err := pe.NewFile(bytes.NewReader(sourceBytes))
		if err != nil {
			return nil, err
		}
		for _, cave := range caves {
			for _, section := range peFile.Sections {
				if cave.Start >= uint64(section.Offset) && cave.End <= uint64(section.Size+section.Offset) &&
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
	return nil, nil
}
