/*
   Auxiliary information emulating Wallet Config
   Structure and contents are not important. Just deinfing some arbitrary data structures
   to do backup
*/

package backuplib

import (
	"math/rand"
)

// Emulated wallet structure
type WalletConfig struct {
	Config map[string][]byte
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

// Init
func initWalletConfig() *WalletConfig {
	var data WalletConfig
	data.Config = make(map[string][]byte)
	for i := 0; i < N_ELEMENTS; i++ {
		st := randStringBytes(13)
		data.Config[st], _ = genRandomBytes((i % 14) + 1)
	}
	return &data
}
