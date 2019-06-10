// +build !windows

package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"
)

func Listen(address string) (int, error) {

	// Create named pipe
	tmpDir, _ := ioutil.TempDir("", "named-pipes")
	namedPipe := filepath.Join(tmpDir, "stdout")
	syscall.Mkfifo(namedPipe, 0600)

	// Open named pipe for reading
	fmt.Println("Opening named pipe for reading")
	var buff bytes.Buffer
	stdout, _ := os.OpenFile(namedPipe, os.O_RDONLY, 0600)

	io.Copy(&buff, stdout)
	stdout.Close()

	return 0, nil

}
