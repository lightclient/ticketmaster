package main

import (
	"context"
	"math/big"
	"sync"

	"github.com/dgraph-io/badger/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

func (t *TicketMaster) pollForNewBlocks(done chan struct{}, wg *sync.WaitGroup) {
	var (
		signer = types.LatestSigner(params.SepoliaChainConfig)
		target = crypto.PubkeyToAddress(t.sk.PublicKey)
		seen   = make(map[common.Hash]bool)
	)
outer:
	for {
		select {
		case <-done:
			break outer
		default:
			block, err := t.client.BlockByNumber(context.Background(), nil)
			if err != nil {
				panic(err)
			}

			// NOTE for later: check if the same ticket has been sent.
			err = t.db.Update(func(txn *badger.Txn) error {
				for _, tx := range block.Transactions() {
					if _, ok := seen[tx.Hash()]; ok {
						// skip if already seen
						continue
					}
					seen[tx.Hash()] = true

					// Check if tx is sent to coordinator.
					if tx.To() != nil && *tx.To() == target {
						if tx.Value().Cmp(big.NewInt(ticketCost)) < 0 {
							log.Info("found transaction with insufficient costs for ticket purchase", "amt", tx.Value())
							continue
						}
						err := txn.Set(tx.Hash().Bytes(), tx.Data())
						if err != nil {
							return err
						}
						from, _ := signer.Sender(tx)
						log.Info("received new tx for ticket purchase", "from", from, "amt", tx.Value(), "hash", tx.Hash())
					}
				}
				return nil
			})
			if err != nil {
				log.Error("error while polling for new blocks", "err", err)
			}

		}
	}
	wg.Done()
}
