package main

import (
	"flag"

	"github.com/Binject/binjection/bj"
)

func main() {
	pipeName := ""
	flag.StringVar(&pipeName, "p", `\\.\pipe\bdf`, "Pipe base name string")
	flag.Parse()

	go ListenPipeDry(pipeName + "dry")
	ListenPipeWet(pipeName + "wet")
}

func Inject(dry []byte) (wet []byte, err error) {
	config := &bj.BinjectConfig{CodeCaveMode: false}
	return bj.Binject(dry, []byte{0, 0, 0, 0}, config)
}
