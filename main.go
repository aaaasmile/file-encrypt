package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

// mi compare in visual code un avviso che i mod non sono settati, allora ho creato il mod con:
// go mod init myencrypt/file-encrypt
// codice adattato da ix.de/zqwx

// Encripta e Decripta un file
// ATTENZIONE: i files criptati possono essere decriptati solo con la chiave privata usata durante la criptazione (file key.pem).
// Encripta
//.\file-encrypt.exe -e -i D:\Hetzner\readme_Hetzner.txt -o D:\scratch\go-lang\crypto\file-encrypt\readme_Hetzner_enc.txt
// Decripta
//.\file-encrypt.exe -d -i D:\scratch\go-lang\crypto\file-encrypt\readme_Hetzner_enc.txt -o D:\scratch\go-lang\crypto\file-encrypt\readme_Hetzner2.txt

const RsaLen = 1024

func Encrypt(plain []byte, pubkey *rsa.PublicKey) []byte {

	//è interessante notare la procedura ibrida della criptazione.
	// Viene generata una nuova chiave random la quale viene poi criptata con la chiave pubblica
	// e messa in testa al file. La chiave della sessione viene criptata con rsa.
	// Mentre il file viene creiptato con aes che è una procedura di cifrazione simmetrica.
	key := make([]byte, 256/8) // AES-256
	io.ReadFull(rand.Reader, key)

	encKey, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, key, nil)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, aesgcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciph := aesgcm.Seal(nil, nonce, plain, nil)
	s := [][]byte{encKey, nonce, ciph}
	return bytes.Join(s, []byte{})
}

func Decrypt(ciph []byte, priv *rsa.PrivateKey) ([]byte, error) {
	//Per primo viene estratta la chiave per la decriptazione via aes.
	// La chiave è in testa al file ed è codificata in rsa. La decriptazione della chiave per
	// la sessione aes è possibile solo via rsa utilizzando la chiave privata in formato pem.
	encKey := ciph[:RsaLen/8]
	ciph = ciph[RsaLen/8:]
	key, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encKey, nil)

	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	nonce := ciph[:aesgcm.NonceSize()]
	ciph = ciph[aesgcm.NonceSize():]

	return aesgcm.Open(nil, nonce, ciph, nil)
}

func savePrivateKeyInFile(file string, priv *rsa.PrivateKey, pwd string) error {
	der := x509.MarshalPKCS1PrivateKey(priv)
	pp := []byte(pwd)
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", der, pp, x509.PEMCipherAES256)
	if err != nil {
		return err
	}
	log.Println("Save the key in ", file)
	return ioutil.WriteFile(file, pem.EncodeToMemory(block), 0644)
}

func privateKeyFromFile(file string, pwd string) (*rsa.PrivateKey, error) {
	der, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(der)

	der, err = x509.DecryptPEMBlock(block, []byte(pwd))
	if err != nil {
		return nil, err
	}
	priv, err := x509.ParsePKCS1PrivateKey(der)
	return priv, nil
}

func main() {
	var encr = flag.Bool("e", false, "Encript file")
	var decr = flag.Bool("d", false, "Decript file")
	var show = flag.Bool("show", false, "Show an encripted file")
	var f1 = flag.String("i", "", "Input file")
	var f2 = flag.String("o", "", "Output file")
	flag.Parse()

	if !*encr && !*decr && !*show {
		log.Println("Action (-e, -d or -show) is not defined")
		os.Exit(0)
	}

	finput := *f1
	if finput == "" {
		log.Println("File name is not provided (-f <fullpath>)")
		os.Exit(0)
	}

	fout := *f2
	if fout == "" && !*show {
		log.Println("File out is not provided (-o <fullpath>)")
		os.Exit(0)
	}

	mySecret := "Serpico78"
	keyFile := "key.pem"
	priv, err := privateKeyFromFile(keyFile, mySecret)
	if err != nil {
		priv, _ = rsa.GenerateKey(rand.Reader, RsaLen)
		err = savePrivateKeyInFile(keyFile, priv, mySecret)
		if err != nil {
			log.Fatal("Unable to save key: ", err)
		}
	}

	pub := priv.PublicKey

	if *encr {
		plain, err := ioutil.ReadFile(finput)
		if err != nil {
			log.Fatalf("Input file %s error: %v", finput, err)
		}
		enc := Encrypt(plain, &pub)
		log.Printf("File %s is encrypted to: %v...", finput, enc[:10])

		err = ioutil.WriteFile(fout, enc, 0644)
		if err != nil {
			log.Fatalln("Write file error: ", err)
		}
		log.Println("File written: ", fout)
	} else if *decr || *show {
		plain, err := ioutil.ReadFile(finput)
		if err != nil {
			log.Fatalf("Input file %s error: %v", finput, err)
		}
		enc, err := Decrypt(plain, priv)
		if err != nil {
			log.Fatalln("Decript error: ", err)
		}
		log.Printf("File %s is dencrypted", finput)
		if *decr {
			err = ioutil.WriteFile(fout, enc, 0644)
			if err != nil {
				log.Fatalln("Write file error: ", err)
			}
			log.Println("File written: ", fout)
		} else if *show {
			log.Println("Decripted file content is:")
			fmt.Printf("The content of '%s' : \n%s\n", finput, enc)
		}
	}

}
