package main

import (
	"log"
	"os"

	"github.com/Binject/binjection/bj"
	"github.com/akamensky/argparse"
)

func main() {

	parser := argparse.NewParser("binjection", "Injects shellcode into PE, ELF, or Mach-O executables and shared libraries")
	srcFile := parser.String("f", "in", &argparse.Options{Required: true, Help: "Input PE, ELF, or Mach-o binary to inject."})
	shellFile := parser.String("s", "sc", &argparse.Options{Required: true,
		Default: "shellcode.bin", Help: "Shellcode to Inject"})

	dstFile := parser.String("o", "out", &argparse.Options{Required: false,
		Default: "injected.out", Help: "Output file"})
	injectionMethod := parser.String("m", "method", &argparse.Options{Required: false,
		Default: "note", Help: "Injection Method (silvio or note)"})
	codeCaveMode := parser.Flag("c", "codeCave", &argparse.Options{Required: false,
		Help: "Auto Code Cave Mode (true/false)"})
	logFile := parser.String("l", "log", &argparse.Options{Required: false,
		Help: "Log to the Given File"})
	if err := parser.Parse(os.Args); err != nil {
		log.Println(parser.Usage(err))
		return
	}
	config := &bj.BinjectConfig{CodeCaveMode: *codeCaveMode}

	if *injectionMethod != "" {
		switch *injectionMethod {
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

	if *logFile != "" {
		logTown, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		defer logTown.Close()
		log.SetOutput(logTown)
		log.Println("Log file started!")
	}

	err := bj.BinjectFile(*srcFile, *dstFile, *shellFile, config)

	log.Println(err)
}
