package conf

import (
	"log"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/kardianos/osext"
)

type Config struct {
	MySecret string
	KeyFname string
	rootPath string
}

var Current = &Config{}

const Appname = "file-encrypt"
const Buildnr = "000.001.20221206-00"

func ReadConfig(configfile string, use_relpath bool) (*Config, error) {
	log.Println("Read config file ", configfile)
	configfile = Current.GetFullPath(configfile, use_relpath)
	_, err := os.Stat(configfile)
	if err != nil {
		return nil, err
	}
	if _, err := toml.DecodeFile(configfile, &Current); err != nil {
		return nil, err
	}

	return Current, nil
}

func (p *Config) GetFullPath(relPath string, use_relpath bool) string {
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
