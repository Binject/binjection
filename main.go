package main

import (
	"flag"
	"log"

	"github.com/awgh/binjection/bj"
)

func main() {

	var srcFile = flag.String("inFile", "a.out", "Input file to inject into")
	flag.StringVar(srcFile, "i", "a.out", "Input file to inject into")
	flag.StringVar(srcFile, "input", "a.out", "Input file to inject into")

	var dstFile = flag.String("dstFile", "injected.out", "Output file")
	flag.StringVar(dstFile, "d", "injected.out", "Output file")

	var shellFile = flag.String("shellFile", "shell.asm", "Shellcode to inject")
	flag.StringVar(shellFile, "s", "shell.asm", "Shellcode to inject")

	var codeCaveMode = flag.Bool("codeCaveMode", false, "Auto Code Cave Mode (true/false)")
	flag.BoolVar(codeCaveMode, "c", false, "Auto Code Cave Mode (true/false)")

	flag.Parse()

	err := bj.Binject(*srcFile, *dstFile, *shellFile, &bj.BinjectConfig{CodeCaveMode: *codeCaveMode})

	log.Println(err)
}
