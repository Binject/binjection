package main

import (
	"flag"
	"log"
	"os"

	"github.com/Binject/binjection/bj"
)

func main() {

	srcFile := ""
	flag.StringVar(&srcFile, "i", "a.out", "Input file")

	dstFile := ""
	flag.StringVar(&dstFile, "o", "injected.out", "Output file")

	shellFile := ""
	flag.StringVar(&shellFile, "s", "shell.asm", "Shellcode to inject")

	codeCaveMode := false
	flag.BoolVar(&codeCaveMode, "c", false, "Auto Code Cave Mode (true/false)")

	logFile := ""
	flag.StringVar(&logFile, "l", "", "send stdout to a log file")

	flag.Parse()

	if logFile != "" {
		logTown, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		defer logTown.Close()
		log.SetOutput(logTown)
		log.Println("Log file started!")
	}

	err := bj.Binject(srcFile, dstFile, shellFile, &bj.BinjectConfig{CodeCaveMode: codeCaveMode})

	log.Println(err)
}
