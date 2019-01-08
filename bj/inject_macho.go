package bj

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
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
	for _, command := range machoFile.Loads {
		rawCommand := command.Raw()
		log.Printf("LoadCmd of command is: %x\n", rawCommand[0])
		if rawCommand[0] == 0x1 {
			log.Printf("32 bit LoadCmdSegment\n")
			mseg32 := macho.Segment32{}
			buf := bytes.NewBuffer(rawCommand)
			err := binary.Read(buf, binary.LittleEndian, &mseg32)
			if err != nil {
				return err
			}
			log.Printf("Your struct sir: %+v\n", mseg32)
		}
		if rawCommand[0] == byte(macho.LoadCmdSegment64) {
			log.Printf("64 bit LoadCmdSegment\n")
			mseg64 := macho.Segment64{}
			buf := bytes.NewBuffer(rawCommand)
			err := binary.Read(buf, binary.LittleEndian, &mseg64)
			if err != nil {
				return err
			}
			log.Printf("Your struct sir: %+v\n", mseg64)
			log.Printf("Your CmdLen is : %d\n", mseg64.Len)
			log.Printf("Vs RawCmd Len: %d\n", len(rawCommand))
			//msegHeader := mseg64.
			//endCmd := mseg64.Offset + uint64(mseg64.Len)
			//fmt.Printf("Your End Cmd is at: %+v\n", endCmd)
		}
	}

	for _, section := range machoFile.Sections {
		// Only parse text sections
		if section.SectionHeader.Seg == "__TEXT" {
			log.Printf("Section looks like: %+v\n", section)
			// Calculate end of sections
			sectEnd := section.SectionHeader.Size + uint64(section.SectionHeader.Offset)
			log.Printf("Section length is: %v\n", section.SectionHeader.Size)
			log.Printf("Section end is at: %v\n", sectEnd)
			// Parse section data for last cmd
			//sectionData, err := section.Data()
			//if err != nil {
			//	return err
			//}

			//fmt.Printf("Section structure looks like: %+v\n", sectionData)

		}
		//sectionData, err := section.Data()
		//if err != nil {
		//	return err
		//}
		//firstHeader := sectionData[:3]
		//fmt.Printf("First four bytes: %+v\n", firstHeader)

		//	if cave.Start >= uint64(section.Offset) && cave.End <= (section.Size+uint64(section.Offset)) &&
		//	header['MagicNumber'] = hex(struct.unpack("<I", self.bin.read(4))[0])

		//	cave.End-cave.Start >= uint64(MIN_CAVE_SIZE) {
		//	log.Printf("Cave found (start/end/size): %d / %d / %d \n", cave.Start, cave.End, cave.End-cave.Start)
	}

	return nil
}
