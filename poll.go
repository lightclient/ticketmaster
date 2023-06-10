package main

import (
	"context"
	"log"
	"math/big"
	"sync"

	"github.com/dgraph-io/badger/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func pollForNewBlocks(done chan struct{}, wg *sync.WaitGroup, db *badger.DB, client *ethclient.Client, tickerMasterAddress common.Address) {
outer:
	for {
		select {
		case <-done:
			break outer
		default:
			block, err := client.BlockByNumber(context.Background(), nil)
			if err != nil {
				log.Fatal(err)
			}

			// NOTE for later: check if the same ticket has been sent.
			err = db.Update(func(txn *badger.Txn) error {
				for _, tx := range block.Transactions() {
					if tx.To() != nil && *tx.To() == tickerMasterAddress {
						if tx.Value().Cmp(big.NewInt(ticketCost)) != 0 {
							log.Printf("found transaction with insufficient costs for ticket purchase: %v", tx.Value())
							continue
						}
						// Transaction with the target recipient found found
						err := txn.Set(tx.Hash().Bytes(), tx.Data())
						if err != nil {
							return err
						}
					}
				}
				return nil
			})
			if err != nil {
				log.Printf("error while polling for new blocks: %v", err)
			}

		}
	}
	wg.Done()
}
