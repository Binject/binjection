package bj

import (
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/h2non/filetype"
)

type BinjectConfig struct {
	CodeCaveMode bool
}

func Binject(sourceFile string, destFile string, shellcode string, config *BinjectConfig) error {

	buf, err := ioutil.ReadFile(sourceFile)
	if err != nil {
		return err
	}

	kind, unknown := filetype.Match(buf)
	if unknown != nil {
		return errors.New("Unknown: " + unknown.Error())

	}

	fmt.Printf("File type: %s. MIME: %s\n", kind.Extension, kind.MIME.Value)
	return nil
}

//
type Binjector interface {
	Inject(sourceFile string, destFile string, shellcode string, mode int)
}
