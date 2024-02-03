package bj

import (
	"testing"
)

var test = "./test/"

func TestELF32(t *testing.T) {
	filename32 := test + "elf32"

	ba, err := BinArchFile(filename32)
	if err != nil {
		t.Fatal("Error with elf32 bin arch detection", err)
	}
	if ba != BinArch32 {
		t.Fatal("Failed to detect bin arch. Should be", BinArch32, "is", ba)
	}
}

// elf 64
func TestELF64(t *testing.T) {
	filename64 := test + "elf64"

	ba64, err := BinArchFile(filename64)
	if err != nil {
		t.Fatal("Error with elf64 bin arch detection", err)
	}
	if ba64 != BinArch64 {
		t.Fatal("Failed to detect bin arch. Should be", BinArch64, "is", ba64)
	}
}

func TestMacho64(t *testing.T) {
	filename64 := test + "macho64"

	ba64, err := BinArchFile(filename64)
	if err != nil {
		t.Fatal("Error with macho64 bin arch detection", err)
	}
	if ba64 != BinArch64 {
		t.Fatal("Failed to detect bin arch. Should be", BinArch64, "is", ba64)
	}
}

// pe32
func TestPE32(t *testing.T) {
	filename32 := test + "pe32"

	ba, err := BinArchFile(filename32)
	if err != nil {
		t.Fatal("Error with pe32 bin arch detection", err)
	}
	if ba != BinArch32 {
		t.Fatal("Failed to detect bin arch. Should be", BinArch32, "is", ba)
	}
}

// pe64
func TestPE64(t *testing.T) {
	filename64 := test + "pe64"

	ba64, err := BinArchFile(filename64)
	if err != nil {
		t.Fatal("Error with pe64 bin arch detection", err)
	}
	if ba64 != BinArch64 {
		t.Fatal("Failed to detect bin arch. Should be", BinArch64, "is", ba64)
	}
}
