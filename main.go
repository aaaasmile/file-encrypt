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
	"io"
	"io/ioutil"
	"log"
	"os"
)

// mi compare in visual code un avviso che i mod non sono settati, allora ho creato il mod con:
// go mod init myencrypt/m
// codice adattato da ix.de/zqwx

const RsaLen = 1024

func Encrypt(plain []byte, pubkey *rsa.PublicKey) []byte {

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
	var decr = flag.Bool("d", false, "Dencript file")
	var f1 = flag.String("f", "", "Input file")
	var f2 = flag.String("o", "", "Output file")
	flag.Parse()

	if !*encr || *decr {
		log.Println("Action (-e or -d) is not defined")
		os.Exit(0)
	}

	finput := *f1
	if finput == "" {
		log.Println("File name is not provided (-f <fullpath>)")
		os.Exit(0)
	}

	fout := *f2
	if fout == "" {
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
	}

}
