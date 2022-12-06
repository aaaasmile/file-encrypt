# file-encrypt
Questo semplice programma è usato per criptare e decriptare file di testo

## Esempio

    go run .\main.go -show  -i .\ciao_enc.txt -relpath

Il comando sopra mostra il contenuto del file ciao_enc.txt.
Il flag _-relpath_ serve per la chiave privata accessibile durante lo sviluppo.
Questo flag si dovrebbe evitare se si mette il path della chiave in un file toml 
e se poi si usa il path assoluto.

## Decriptare files in altri folder
Per mostrare il contenuto criptato di un file in un altro folder, si usa: 

    D:\Projects\go-lang\crypto\file-encrypt\file-encrypt.exe -show  -i .\<nome_file>

## TODO
Implementa un comando merge che prenda un file criptato come primo valore ed esegua un 
merge con un file non criptato. Il riultato viene messo in un nuovo file criptato che si
chiama come il primo file:

    Contenuto di ciao_enc.txt
    ciao
    Contenuto di ciao.txt
    ciao2
    Risulato criptato
    ciao
    ciao2

Esempio comando: -merge -i ciao_enc.txt -clear ciao.txt -o ciao_enc.txt

### Credits
Codice adattato da ix.de/zqwx

