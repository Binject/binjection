package bj

import (
	"bytes"
	"errors"
	"io/ioutil"
	"log"
)

const (
	// ERROR - constant for an error
	ERROR = iota
	// ELF - constant for ELF binary format
	ELF = iota
	// MACHO - constant for Mach-O binary format
	MACHO = iota
	// PE - constant for PE binary format
	PE = iota
)

// BinaryMagic - Identifies the Binary Format of a file by looking at its magic number
func BinaryMagic(filename string) (int, error) {

	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return ERROR, err
	}

	log.Println(buf[:4])

	if bytes.Equal(buf[:4], []byte{0x7F, 'E', 'L', 'F'}) {
		return ELF, nil
	}

	if bytes.Equal(buf[:3], []byte{0xfe, 0xed, 0xfa}) {
		if buf[3] == 0xce || buf[3] == 0xcf {
			// FE ED FA CE - Mach-O binary (32-bit)
			// FE ED FA CF - Mach-O binary (64-bit)
			return MACHO, nil
		}
	}

	if bytes.Equal(buf[1:4], []byte{0xfa, 0xed, 0xfe}) {
		if buf[0] == 0xce || buf[0] == 0xcf {
			// CE FA ED FE - Mach-O binary (reverse byte ordering scheme, 32-bit)
			// CF FA ED FE - Mach-O binary (reverse byte ordering scheme, 64-bit)
			return MACHO, nil
		}
	}

	if bytes.Equal(buf[:2], []byte{0x4d, 0x5a}) {
		return PE, nil
	}

	return ERROR, errors.New("Unknown Binary Format")
}
