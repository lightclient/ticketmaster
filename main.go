package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/dgraph-io/badger/v3"
)

type Address [20]byte
type Hash [32]byte

func main() {
	if len(os.Args) < 3 {
		exit("usage: <db> <rsa-key>")
	}
	var (
		dbPath  = os.Args[1]
		keyFile = os.Args[2]
	)
	db, err := badger.Open(badger.DefaultOptions(dbPath))
	if err != nil {
		exit("unable to open db at %s: %v", err)
	}
	pk, err := loadRSAPrivateKeyFromFile(keyFile)
	if err != nil {
		exit("unable to read rsa key from %s: %v")
	}

	handler := &TicketMaster{db: db, pk: pk}
	log.Fatal(http.ListenAndServe(":8000", handler))
}

func loadRSAPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing RSA private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func exit(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format, a)
	os.Exit(1)
}
