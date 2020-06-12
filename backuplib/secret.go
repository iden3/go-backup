/*

  Secret Sharing wrapper functionality

*/

package backuplib

import (
	"github.com/iden3/go-backup/ff"
	"github.com/iden3/go-backup/secret"
)

type Share struct {
	Px int
	Py []byte
}

type Shares struct {
	Data []Share
}

type Secret struct {
	secret.Shamir
}

func GetNShares() int {
	shares := GetShares()
	return len(shares.Data)
}

func GetShare(n int) *Share {
	shares := GetShares()
	if n < len(shares.Data) {
		return &shares.Data[n]
	} else {
		return nil
	}
}

// Generate shares from secret
func GenerateShares(secret []byte) {
	// convert secret to right format
	secretFF, _ := ff.NewElement(PRIME)
	secretFF.FromByte(secret)
	secretCfg := GetSecretCfg()
	sharesGo, _ := secretCfg.GenerateShares(secretFF)
	sharesMobile := GetShares()
	sharesMobile.Data = fromShares(sharesGo)
	SetShares(sharesMobile)
}

func toShares(shares *Shares) []secret.Share {
	sharesGo := make([]secret.Share, 0)
	secretConfig := GetSecretCfg()
	for _, share := range shares.Data {
		newEl, _ := ff.NewElement(secretConfig.GetElType())
		newShareGo := secret.Share{Px: share.Px,
			Py: newEl.FromByte(share.Py)}
		sharesGo = append(sharesGo, newShareGo)
	}

	return sharesGo
}

func fromShares(shares []secret.Share) []Share {
	sharesMobile := make([]Share, 0)
	for _, share := range shares {
		newShareMobile := Share{Px: share.Px,
			Py: share.Py.ToByte()}
		sharesMobile = append(sharesMobile, newShareMobile)
	}
	return sharesMobile
}

// Generate secret from shares
func GenerateKey() []byte {
	sharesGo := toShares(GetShares())
	return generateKey(sharesGo, GetSecretCfg())
}

func generateKey(shares []secret.Share, sharingCfg secret.SecretSharer) []byte {
	sharesPool := make([]secret.Share, 0)
	for _, share := range shares {
		sharesPool = append(sharesPool, share)
		if len(sharesPool) == sharingCfg.GetMinShares() {
			break
		}
	}
	secret, err := sharingCfg.GenerateSecret(sharesPool)
	if err != nil {
		panic(err)
	}

	return secret.ToByte()
}

func initSecretCfg() {
	var secretCfg Secret
	err := secretCfg.NewConfig(MIN_N_SHARES, MAX_N_SHARES, PRIME)
	if err != nil {
		panic(err)
	}
	SetSecretCfg(&secretCfg)
}

func initSecretShares() {
	var shares Shares
	shareData := make([]Share, 0)
	shares.Data = shareData
	SetShares(&shares)
}
