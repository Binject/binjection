package main

import (
	"flag"
	"log"
	"os"

	"github.com/Binject/binjection/bj"
)

func main() {

	srcFile := ""
	flag.StringVar(&srcFile, "i", "a.out", "Input File")

	dstFile := ""
	flag.StringVar(&dstFile, "o", "injected.out", "Output File")

	shellFile := ""
	flag.StringVar(&shellFile, "s", "shell.asm", "Shellcode to Inject")

	injectionMethod := ""
	flag.StringVar(&injectionMethod, "m", "method", "Injection Method: silvio, note, gonote")

	codeCaveMode := false
	flag.BoolVar(&codeCaveMode, "c", false, "Auto Code Cave Mode (true/false)")

	logFile := ""
	flag.StringVar(&logFile, "l", "", "Log to the Given File")

	flag.Parse()

	config := &bj.BinjectConfig{CodeCaveMode: codeCaveMode}

	if injectionMethod != "" {
		switch injectionMethod {
		case "silvio":
			config.InjectionMethod = bj.SilvioInject

		case "note":
			config.InjectionMethod = bj.PtNoteInject

		//case "gonote":
		//config.InjectionMethod = bj.GolangNoteInject

		default:
			log.Fatal("Invalid Injection Method")
		}
	}

	if logFile != "" {
		logTown, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		defer logTown.Close()
		log.SetOutput(logTown)
		log.Println("Log file started!")
	}

	err := bj.Binject(srcFile, dstFile, shellFile, config)

	log.Println(err)
}
