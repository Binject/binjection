package main

import (
	"flag"
	"log"

	"github.com/Binject/binjection/bj"
	"github.com/Binject/debug/elf"
	"github.com/Binject/debug/macho"
	"github.com/Binject/debug/pe"
)

func main() {
	srcFile := ""
	flag.StringVar(&srcFile, "i", "a.out", "Input file to inject into")
	dstFile := ""
	flag.StringVar(&dstFile, "o", "injected.out", "Output file")
	flag.Parse()

	t, err := bj.BinaryMagic(srcFile)
	if err != nil {
		log.Fatal(err)
	}
	switch t {
	case bj.ELF:
		err = ElfClone(srcFile, dstFile)
	case bj.MACHO:
		err = MachoClone(srcFile, dstFile)
	case bj.PE:
		err = PeClone(srcFile, dstFile)
	default:
		log.Fatal("Unknown binary format")
	}
	log.Println(err)
}

// ElfClone - Clone an ELF binary
func ElfClone(sourceFile string, destFile string) error {

	elfFile, err := elf.Open(sourceFile)
	if err != nil {
		return err
	}

	return elfFile.Write(destFile)
}

// MachoClone - Clone an Macho binary
func MachoClone(sourceFile string, destFile string) error {

	machoFile, err := macho.Open(sourceFile)
	if err != nil {
		return err
	}

	return machoFile.Write(destFile)
}

// PeClone - Clone a PE binary
func PeClone(sourceFile string, destFile string) error {

	peFile, err := pe.Open(sourceFile)
	if err != nil {
		return err
	}

	return peFile.Write(destFile)
}
