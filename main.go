package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/dgraph-io/badger/v3"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	if len(os.Args) < 5 {
		exit("usage: <db> <rsa-key> <ecdsa-key> <rpc url>")
	}
	var (
		dbPath    = os.Args[1]
		pemFile   = os.Args[2]
		ecdsaFile = os.Args[3]
		rpcUrl    = os.Args[4]
	)

	// Open database.
	db, err := badger.Open(badger.DefaultOptions(dbPath))
	if err != nil {
		exit("unable to open db at %s: %v", dbPath, err)
	}
	defer db.Close()

	// Read RSA key.
	rsaKey, err := loadRSAPrivateKeyFromFile(pemFile)
	if err != nil {
		exit("unable to read rsa key from %s: %v", pemFile, err)
	}
	fmt.Println("RSA Public Key:")
	fmt.Println("N:", rsaKey.N)
	fmt.Println("E:", rsaKey.E)

	// Read ECDSA key.
	ecdsaKey, err := loadECDSAPrivateKeyFromFile(ecdsaFile)
	if err != nil {
		exit("unable to read ecdsa key from %s: %v", ecdsaFile, err)
	}
	fmt.Println("TicketMaster address: ", crypto.PubkeyToAddress(ecdsaKey.PublicKey).Hex())

	// Open JSON-RPC connection to client.
	client, err := ethclient.Dial(rpcUrl)
	if err != nil {
		exit("error creating the RPC client: %v", err)
	}
	tm := &TicketMaster{db: db, rsa: rsaKey, client: client}

	// Spin up thread to watch for new payments.
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go tm.pollForNewBlocks(done, &wg)
	defer func() {
		done <- struct{}{}
	}()
	fmt.Println("listening 127.0.0.1:8000")

	log.Fatal(http.ListenAndServe(":8000", tm))
	done <- struct{}{}
	wg.Wait()
}

func loadRSAPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode pem block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func loadECDSAPrivateKeyFromFile(filename string) (*ecdsa.PrivateKey, error) {
	key, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return crypto.HexToECDSA(strings.TrimSpace(string(key)))
}

func exit(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
