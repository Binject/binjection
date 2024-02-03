package bj

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"

	"github.com/fatih/color"
)

const (
	// ERROR - constant for an error
	ERROR = iota
	// ELF - constant for ELF binary format
	ELF = iota
	// MACHO - constant for Mach-O binary format
	MACHO = iota
	// FAT - constant for FAT/Mach-O binary format
	FAT = iota
	// PE - constant for PE binary format
	PE = iota
	// MIN_CAVE_SIZE - the smallest a code cave can be
	MIN_CAVE_SIZE = 94
)

const (
	// ERROR - constant for an error
	Error = iota
	// 32 binary architecture
	BinArch32 = iota
	// 64 binary architecture
	BinArch64 = iota
)

var (
	// Set up colors
	cyan = color.New(color.FgCyan)
	blue = color.New(color.FgBlue)
	red  = color.New(color.FgRed)
)

// Cave - structure describing a code cave
type Cave struct {
	Start, End uint64
}

// BinArchFile - Identifies the binary architecture of a file by looking at its header
func BinArchFile(filename string) (int, error) {

	buf, err := os.ReadFile(filename)
	if err != nil {
		return ERROR, err
	}
	return BinArch(buf)
}

// BinaryMagicFile - Identifies the Binary Format of a file by looking at its magic number
func BinaryMagicFile(filename string) (int, error) {

	buf, err := os.ReadFile(filename)
	if err != nil {
		return ERROR, err
	}
	return BinaryMagic(buf)
}

// BinArch - Identifies the binary architecture of a file by looking at its magic number
func BinArch(buf []byte) (int, error) {
	bm, err := BinaryMagic(buf)
	if err != nil {
		return Error, err
	}

	switch bm {
	case ELF:
		if bytes.Equal(buf[4:5], []byte{0x1}) {
			return BinArch32, nil
		} else if bytes.Equal(buf[4:5], []byte{0x2}) {
			return BinArch64, nil
		} else {
			return Error, errors.New("Possibly ELF format but didn't find binary arch type")
		}
	case MACHO:
		if bytes.Equal(buf[:4], []byte{0xfe, 0xed, 0xfa, 0xce}) || bytes.Equal(buf[:4], []byte{0xce, 0xfa, 0xed, 0xfe}) {
			return BinArch32, nil
		} else if bytes.Equal(buf[:4], []byte{0xfe, 0xed, 0xfa, 0xcf}) || bytes.Equal(buf[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) {
			return BinArch64, nil
		} else {
			return Error, errors.New("Possibly MACH-O format but didn't find binary arch type")
		}
	case PE:
		// at 0x3c is the offset for the pe header as a DWORD 32 bit uint
		offset := binary.LittleEndian.Uint32(buf[0x3c : 0x3c+4])
		if bytes.Equal(buf[offset+4:offset+6], []byte{0x64, 0x86}) {
			return BinArch64, nil
		} else if bytes.Equal(buf[offset+4:offset+6], []byte{0x4c, 0x01}) {
			return BinArch32, nil
		} else {
			return Error, errors.New("Possibly PE format but didn't find binary arch type")
		}
	case FAT:
		return BinArch32, nil
	default:
		return Error, errors.New("Unknown Binary Format")
	}
}

// BinaryMagic - Identifies the Binary Format of a file by looking at its magic number
func BinaryMagic(buf []byte) (int, error) {

	//log.Printf("%x\n", buf[:4])

	if bytes.Equal(buf[:4], []byte{0x7F, 'E', 'L', 'F'}) {
		log.Printf("ELF\n")
		return ELF, nil
	}

	if bytes.Equal(buf[:3], []byte{0xfe, 0xed, 0xfa}) {
		if buf[3] == 0xce || buf[3] == 0xcf {
			// FE ED FA CE - Mach-O binary (32-bit)
			// FE ED FA CF - Mach-O binary (64-bit)
			log.Printf("MACHO\n")
			return MACHO, nil
		}
	}

	if bytes.Equal(buf[1:4], []byte{0xfa, 0xed, 0xfe}) {
		if buf[0] == 0xce || buf[0] == 0xcf {
			// CE FA ED FE - Mach-O binary (reverse byte ordering scheme, 32-bit)
			// CF FA ED FE - Mach-O binary (reverse byte ordering scheme, 64-bit)
			log.Printf("MACHO\n")
			return MACHO, nil
		}
	}

	if bytes.Equal(buf[:2], []byte{0x4d, 0x5a}) {
		log.Printf("PE\n")
		return PE, nil
	}

	if bytes.Equal(buf[:3], []byte{0xca, 0xfe, 0xba}) {
		if buf[3] == 0xbe || buf[3] == 0xbf {
			log.Println(red.Sprintf("FAT\n"))
			return FAT, nil
		}
	}

	if bytes.Equal(buf[1:4], []byte{0xba, 0xfe, 0xca}) {
		if buf[0] == 0xbe || buf[0] == 0xbf {
			log.Println(red.Sprintf("FAT\n"))
			return FAT, nil
		}
	}

	return ERROR, errors.New("Unknown Binary Format")
}

// FindCavesFile - finds code caves in a file
func FindCavesFile(sourceFile string) ([]Cave, error) {
	buf, err := os.ReadFile(sourceFile)
	if err != nil {
		return nil, err
	}
	return FindCaves(buf)
}

// FindCaves - finds code caves in a byte array
func FindCaves(sourceBytes []byte) ([]Cave, error) {
	var caves []Cave

	count := 1
	caveStart := uint64(0)
	for i := uint64(0); i < uint64(len(sourceBytes)); i++ {
		switch sourceBytes[i] {
		case 0:
			if count == 1 {
				caveStart = i
			}
			count++
		default:
			if count >= MIN_CAVE_SIZE {
				caves = append(caves, Cave{Start: caveStart, End: i})
			}
			count = 1
		}
	}
	return caves, nil
}
