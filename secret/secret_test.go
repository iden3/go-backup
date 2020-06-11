package secret

import (
	"math/rand"
	"testing" 
        "reflect"

	"github.com/iden3/go-backup/ff"
)

func TestShamirOK(t *testing.T) {
	// Generate Shamir config
	var min_shares, max_shares, prime = 3, 6, ff.FF_BN256_FP
	var cfg Shamir
	err := cfg.NewConfig(min_shares, max_shares, prime)
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
        for _, share := range(shares) {
           share_byte := share.Marshal(ff.FF_BN256_FP)
           share_rec := &Share{}
           share_rec, err = share_rec.Unmarshal(share_byte)
           if err != nil || !reflect.DeepEqual(*share_rec, share) {
		t.Error("Error in Marshall/Unmarshal")
          }
        }

	// select shares to regenerate secret
	for iter := 0; iter < 10; iter++ {
		selected_shares := shuffleShares(shares, min_shares)

		// generate key
		new_secret, err3 := cfg.GenerateSecret(selected_shares)
		if err3 != nil {
			t.Error(err3)
		}
		if !secret.Equal(new_secret) {
			t.Error("Secrets not equal")
		} 
	}
}

func TestShamirKO(t *testing.T) {
	// Generate Shamir config
	var min_shares, max_shares, prime = 3, 6, ff.FF_BN256_FQ
	var cfg Shamir
	err := cfg.NewConfig(min_shares, max_shares, prime)
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
		selected_shares := shuffleShares(shares, min_shares-1)

		// generate key
		new_secret, err3 := cfg.GenerateSecret(selected_shares)
		if err3 != nil {
			t.Error(err3)
		}
		if secret.Equal(new_secret) {
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
			new_idx := rand.Intn(nshares)
			for _, share := range selected {
				if share.Px == pool[new_idx].Px {
					found = true
					continue
				}
			}
			if !found {
				selected = append(selected, pool[new_idx])
			}
		}
	}
	return selected
}
