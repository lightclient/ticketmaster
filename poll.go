package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"sync"

	"github.com/dgraph-io/badger/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func (t *TicketMaster) pollForNewBlocks(done chan struct{}, wg *sync.WaitGroup) {
	seen := make(map[common.Hash]bool)
outer:
	for {
		select {
		case <-done:
			break outer
		default:
			block, err := t.client.BlockByNumber(context.Background(), nil)
			if err != nil {
				log.Fatal(err)
			}

			// NOTE for later: check if the same ticket has been sent.
			err = t.db.Update(func(txn *badger.Txn) error {
				for _, tx := range block.Transactions() {
					if _, ok := seen[tx.Hash()]; ok {
						continue
					}
					seen[tx.Hash()] = true

					if tx.To() != nil && *tx.To() == crypto.PubkeyToAddress(t.pk.PublicKey) {
						if tx.Value().Cmp(big.NewInt(ticketCost)) != 0 {
							log.Printf("found transaction with insufficient costs for ticket purchase: %v", tx.Value())
							continue
						}
						// Transaction with the target recipient found found
						err := txn.Set(tx.Hash().Bytes(), tx.Data())
						if err != nil {
							return err
						}
						fmt.Println("new valid tx found", tx.Hash().Hex())
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
