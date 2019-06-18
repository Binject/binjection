// +build !windows

package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"syscall"
)

func MakePipe(pipename string) string {
	// Create named pipe
	tmpDir, _ := ioutil.TempDir("", "named-pipes")
	namedPipe := filepath.Join(tmpDir, pipename)
	syscall.Mkfifo(namedPipe, 0600)
	return namedPipe
}

func ListenPipeDry(namedPipe string) {
	// Open named pipe for reading
	fmt.Println("Opening named pipe for reading")
	var buff bytes.Buffer
	for {
		stdout, err := os.OpenFile(namedPipe, os.O_RDONLY, 0600)
		if err != nil {
			log.Fatalf("Open(%s) failed: %v", namedPipe, err)
		}
		io.Copy(&buff, stdout)
		stdout.Close()

		go handleDryConnection(buff)
	}
}

func ListenPipeWet(namedPipe string) {
	// Open named pipe for writing
	fmt.Println("Opening named pipe for writing")
	for {
		if lastBytes != nil {
			stdout, err := os.OpenFile(namedPipe, os.O_WRONLY, 0600)
			if err != nil {
				log.Fatalf("Open(%s) failed: %v", namedPipe, err)
			}
			_, err = io.Copy(stdout, bytes.NewReader(lastBytes))
			stdout.Close()

			log.Println("Wrote wet bytes: ", len(lastBytes))

			if err != nil {
				log.Fatalf("Error on writing to pipe: %v", err)
			}
			lastBytes = nil
		}
	}
}

var lastBytes []byte

func handleDryConnection(buff bytes.Buffer) {

	i, err := Inject(buff.Bytes())
	if err != nil {
		log.Fatalf("Error injecting: %v", err)
	}
	log.Println("Set lastBytes: ", len(lastBytes))
	lastBytes = i
}
