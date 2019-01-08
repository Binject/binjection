package main

import (
	"flag"
	"log"
	"os"

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

	var codeCaveMode = flag.Bool("codeCaveMode", true, "Auto Code Cave Mode (true/false)")
	flag.BoolVar(codeCaveMode, "c", true, "Auto Code Cave Mode (true/false)")

	var logFile = flag.String("logFile", "", "send stdout to a log file")
	flag.StringVar(logFile, "l", "", "send stdout to a log file")

	flag.Parse()

	if *logFile != "" {
		logTown, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		defer logTown.Close()
		log.SetOutput(logTown)
		log.Println("Log file started!")
	}

	err := bj.Binject(*srcFile, *dstFile, *shellFile, &bj.BinjectConfig{CodeCaveMode: *codeCaveMode})

	log.Println(err)
}
