package conf

import (
	"log"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	MySecret string
	KeyFname string
}

var Current = &Config{}

const Appname = "file-encrypt"
const Buildnr = "000.001.20221206-00"

func ReadConfig(configfile string) (*Config, error) {
	log.Println("Read config file ", configfile)
	_, err := os.Stat(configfile)
	if err != nil {
		return nil, err
	}
	if _, err := toml.DecodeFile(configfile, &Current); err != nil {
		return nil, err
	}

	return Current, nil
}
