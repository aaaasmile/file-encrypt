package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/aaaasmile/file-encrypt/conf"
	"github.com/aaaasmile/file-encrypt/procenc"
)

func checkFilesNotEmpty(finp, fout string) error {
	if finp == "" {
		return fmt.Errorf("-i argument is missed (input file)")
	}
	if fout == "" {
		return fmt.Errorf("-o argument is missed (output file)")
	}
	return nil
}

func main() {
	var encr = flag.Bool("e", false, "Encript file")
	var decr = flag.Bool("d", false, "Decript file")
	var show = flag.Bool("show", false, "Show an encripted file")
	var finput = flag.String("i", "", "Input file (encripted/decripted file)")
	var foutput = flag.String("o", "", "Output file (key or encrypted/decripted file)")
	var relpath = flag.Bool("relpath", false, "Use relative path. Used it in dev mode or when the exe is called in the same folder as the key")
	var genkey = flag.Bool("genkey", false, "Create a private key")
	var configfile = flag.String("config", "config.toml", "Configuration file path")
	var ver = flag.Bool("version", false, "Prints current version")

	flag.Parse()
	if *decr && *show {
		log.Fatal("Use -d or -show, but not together")
	}

	if *ver {
		fmt.Printf("%s, version: %s", conf.Appname, conf.Buildnr)
		os.Exit(0)
	}

	if !*encr && !*decr && !*show {
		log.Println("Action (-e, -d or -show) is not defined")
		os.Exit(0)
	}
	_, err := conf.ReadConfig(*configfile)
	if err != nil {
		log.Fatal("Config file error: ", err)
	}
	if *genkey {
		if err := checkFilesNotEmpty(" ", *foutput); err != nil {
			log.Fatal("Argument not specified: ", err)
		}
		proc := procenc.NewProcEncWithoutKey(conf.Current.MySecret)
		if err := proc.GenerateKey(*foutput); err != nil {
			log.Fatal("Error on generate key: ", err)
		}
	}

	proc, err := procenc.NewProcEnc(conf.Current.MySecret, conf.Current.KeyFname, *relpath)
	if err != nil {
		log.Fatal(err)
	}

	if *encr {
		if err := checkFilesNotEmpty(*finput, *foutput); err != nil {
			log.Fatal("Argument not specified: ", err)
		}
		if err := proc.EncryptFile(*finput, *foutput); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}
	if *decr {
		if err := checkFilesNotEmpty(*finput, *foutput); err != nil {
			log.Fatal("Argument not specified: ", err)
		}
		if err := proc.DecryptFile(*finput, *foutput); err != nil {
			log.Fatal("Decrypt error: ", err)
		}
		os.Exit(0)
	}
	if *show {
		if err := checkFilesNotEmpty(*finput, " "); err != nil {
			log.Fatal("Argument not specified: ", err)
		}
		if err := proc.ShowDecryptedFile(*finput); err != nil {
			log.Fatal("Show file error: ", err)
		}
		os.Exit(0)
	}

}
