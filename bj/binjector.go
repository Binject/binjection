package bj

// BinjectConfig - Configuration Settings for the Binject modules
type BinjectConfig struct {
	CodeCaveMode bool
}

// Binject - Inject shellcode into a binary
func Binject(sourceFile string, destFile string, shellcodeFile string, config *BinjectConfig) error {

	binType, err := BinaryMagic(sourceFile)
	var binject func(string, string, string, *BinjectConfig) error
	switch binType {
	case ELF:
		binject = ElfBinject
	case MACHO:
		binject = MachoBinject
	case PE:
		binject = PeBinject
	case FAT:
		binject = FatBinject
	case ERROR:
		return err
	}
	return binject(sourceFile, destFile, shellcodeFile, config)
}
