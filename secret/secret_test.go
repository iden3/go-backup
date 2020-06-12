package secret

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/iden3/go-backup/ff"
)

func TestShamirOK(t *testing.T) {
	// Generate Shamir config
	var minShares, maxShares, prime = 3, 6, ff.FF_BN256_FP
	var cfg Shamir
	err := cfg.NewConfig(minShares, maxShares, prime)
	if err != nil {
		t.Error(err)
	}

	// Secret
	secret, err1 := ff.NewElement(prime)
	if err1 != nil {
		t.Error(err1)
	}
	secret.SetRandom().ToMont()

	// Generate Shares
	shares, err2 := cfg.GenerateShares(secret)
	if err2 != nil {
		t.Error(err2)
	}
	// Marshal/Unmarshal shares
	for _, share := range shares {
		shareByte := share.Marshal(ff.FF_BN256_FP)
		shareRec := &Share{}
		shareRec, err = shareRec.Unmarshal(shareByte)
		if err != nil || !reflect.DeepEqual(*shareRec, share) {
			t.Error("Error in Marshall/Unmarshal")
		}
	}

	// select shares to regenerate secret
	for iter := 0; iter < 10; iter++ {
		selectedShares := shuffleShares(shares, minShares)

		// generate key
		newSecret, err3 := cfg.GenerateSecret(selectedShares)
		if err3 != nil {
			t.Error(err3)
		}
		if !secret.Equal(newSecret) {
			t.Error("Secrets not equal")
		}
	}
}

func TestShamirKO(t *testing.T) {
	// Generate Shamir config
	var minShares, maxShares, prime = 3, 6, ff.FF_BN256_FQ
	var cfg Shamir
	err := cfg.NewConfig(minShares, maxShares, prime)
	if err != nil {
		t.Error(err)
	}

	// Secret
	secret := cfg.NewSecret()

	// Generate Shares
	shares, err2 := cfg.GenerateShares(secret)
	if err2 != nil {
		t.Error(err2)
	}

	// select insufficient shares to regenerate secret
	for iter := 0; iter < 10; iter++ {
		selectedShares := shuffleShares(shares, minShares-1)

		// generate key
		newSecret, err3 := cfg.GenerateSecret(selectedShares)
		if err3 != nil {
			t.Error(err3)
		}
		if secret.Equal(newSecret) {
			t.Error("Secrets are equal")
		}
	}
}

func shuffleShares(pool []Share, n int) []Share {
	selected := make([]Share, 0)
	nshares := len(pool)
	for i := 0; i < n; i++ {
		found := true
		for found {
			found = false
			newIdx := rand.Intn(nshares)
			for _, share := range selected {
				if share.Px == pool[newIdx].Px {
					found = true
					continue
				}
			}
			if !found {
				selected = append(selected, pool[newIdx])
			}
		}
	}
	return selected
}
