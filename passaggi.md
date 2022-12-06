# file-encrypt
Questo semplice programma è usato per criptare e decriptare file di testo.


## Esempio

    go run .\main.go -show  -i .\ciao_enc.txt -relpath

Il comando sopra mostra il contenuto del file ciao_enc.txt.
Il flag _-relpath_ serve per trovare il file config durante lo sviluppo. 
Perché? La ragione è che uso il tool non nella sua directory, ma fuori dove si trova
il file criptato.

## Decriptare files in altri folder
Per mostrare il contenuto criptato di un file in un altro folder, si usa: 

    D:\Projects\go-lang\crypto\file-encrypt\file-encrypt.exe -show  -i .\<nome_file>

## Merge
Implementa un comando merge che prenda un file in chiaro ed esegue un merge
con un file criptato.

    .\file-encrypt.exe -merge -i .\ciao2.txt -o .\ciao_enc.txt 

Come file di input si usa il file in chiaro mentre la destinazione è un file già criptato.
Se la destinazione è un file vuoto o in chiaro non viene fatto il merge. 
Per questa funzionalità si usa il comando _-enc_ che mi sembra più adeguato nel
cercare di stabilire se un file di destinazione è criptato oppure no (per esempio la chiave non è corretta).

### Credits
Codice adattato da ix.de/zqwx

