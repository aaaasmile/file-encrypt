package procenc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"

	"github.com/kardianos/osext"
)

type ProcEnc struct {
	RsaLen     int
	rootPath   string
	secretSalt string
	privKey    *rsa.PrivateKey
}

func NewProcEnc(secretSalt string, keyFile string, relPath bool) (*ProcEnc, error) {
	proc := NewProcEncWithoutKey(secretSalt)
	keyFile = proc.GetFullPath(keyFile, relPath)

	priv, err := privateKeyFromFile(keyFile, secretSalt)
	if err != nil {
		log.Println("Error unable to get private key")
		return nil, err
	}
	proc.privKey = priv

	return proc, nil
}

func NewProcEncWithoutKey(secretSalt string) *ProcEnc {
	proc := ProcEnc{
		RsaLen:     1024,
		secretSalt: secretSalt,
	}
	return &proc
}

func (p *ProcEnc) GenerateKey(outkeyFile string) error {
	if outkeyFile == "" {
		return fmt.Errorf("Destination key file not provided")
	}
	priv, _ := rsa.GenerateKey(rand.Reader, p.RsaLen)
	return savePrivateKeyInFile(outkeyFile, priv, p.secretSalt)
}

func (p *ProcEnc) GetFullPath(relPath string, use_relpath bool) string {
	if use_relpath {
		return relPath
	}
	if p.rootPath == "" {
		var err error
		p.rootPath, err = osext.ExecutableFolder()
		if err != nil {
			log.Fatalf("ExecutableFolder failed: %v", err)
		}
		log.Println("Executable folder (rootdir) is ", p.rootPath)
	}
	r := filepath.Join(p.rootPath, relPath)
	return r
}

func (p *ProcEnc) EncryptFile(finput string, foutput string) error {
	plain, err := ioutil.ReadFile(finput)
	if err != nil {
		return fmt.Errorf("Input file %s error: %v", finput, err)
	}
	pub := p.privKey.PublicKey
	enc, err := encrypt(plain, &pub)
	if err != nil {
		return err
	}
	log.Printf("File %s is encrypted to: %v...", finput, enc[:10])

	err = ioutil.WriteFile(foutput, enc, 0644)
	if err != nil {
		return fmt.Errorf("Write file error: %v", err)
	}
	log.Println("File written: ", foutput)
	return nil
}

func (p *ProcEnc) DecryptFile(finput string, foutput string) error {
	enc, err := p.decryptFile(finput)
	if err != nil {
		return err
	}
	log.Printf("File %s is decrypted", finput)

	err = ioutil.WriteFile(foutput, enc, 0644)
	if err != nil {
		return fmt.Errorf("Write file error: %v", err)
	}
	log.Println("File written: ", foutput)
	return nil
}

func (p *ProcEnc) ShowDecryptedFile(finput string) error {
	enc, err := p.decryptFile(finput)
	if err != nil {
		return err
	}
	fmt.Printf("The content of '%s' : \n%s\n", finput, enc)
	return nil
}

func (p *ProcEnc) decryptFile(finput string) ([]byte, error) {
	plain, err := ioutil.ReadFile(finput)
	if err != nil {
		return nil, fmt.Errorf("Input file %s error: %v", finput, err)
	}
	return decrypt(plain, p.privKey, p.RsaLen)
}

func privateKeyFromFile(file string, pwd string) (*rsa.PrivateKey, error) {
	der, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	log.Println("Using key: ", file)

	block, _ := pem.Decode(der)

	der, err = x509.DecryptPEMBlock(block, []byte(pwd))
	if err != nil {
		return nil, err
	}
	priv, err := x509.ParsePKCS1PrivateKey(der)
	return priv, nil
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

func encrypt(plain []byte, pubkey *rsa.PublicKey) ([]byte, error) {

	//è interessante notare la procedura ibrida della criptazione.
	// Viene generata una nuova chiave random la quale viene poi criptata con la chiave pubblica
	// e messa in testa al file. La chiave della sessione viene criptata con rsa.
	// Mentre il file viene creiptato con aes che è una procedura di cifrazione simmetrica.
	key := make([]byte, 256/8) // AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, key, nil)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciph := aesgcm.Seal(nil, nonce, plain, nil)
	s := [][]byte{encKey, nonce, ciph}
	return bytes.Join(s, []byte{}), nil
}

func decrypt(ciph []byte, priv *rsa.PrivateKey, RsaLen int) ([]byte, error) {
	//Per primo viene estratta la chiave per la decriptazione via aes.
	// La chiave è in testa al file ed è codificata in rsa. La decriptazione della chiave per
	// la sessione aes è possibile solo via rsa utilizzando la chiave privata in formato pem.
	encKey := ciph[:RsaLen/8]
	ciph = ciph[RsaLen/8:]
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encKey, nil)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := ciph[:aesgcm.NonceSize()]
	ciph = ciph[aesgcm.NonceSize():]

	return aesgcm.Open(nil, nonce, ciph, nil)
}
