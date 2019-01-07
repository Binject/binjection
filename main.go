package main

import (
	"flag"
	"log"

	"github.com/awgh/binjection/bj"
)

func main() {

	var srcFile, dstFile, shellFile string
	var codeCaveMode bool

	flag.StringVar(&srcFile, "srcFile", "a.out", "Input file to inject into")
	flag.StringVar(&dstFile, "dstFile", "injected.out", "Output file")
	flag.StringVar(&shellFile, "shellFile", "shell.asm", "Shellcode to inject")
	flag.BoolVar(&codeCaveMode, "codeCaveMode", false, "Auto Code Cave Mode (true/false)")
	flag.Parse()

	err := bj.Binject(srcFile, dstFile, shellFile, &bj.BinjectConfig{CodeCaveMode: codeCaveMode})

	log.Println(err)
}
