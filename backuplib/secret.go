/*
 Utility functions to convert between types.
 secret sharing package needs to be improved to
 support more convenient data types and avoid so much conversion
*/

package backuplib

import (
	"github.com/iden3/go-backup/ff"
	"github.com/iden3/go-backup/secret"
)

type Share struct {
   Px   int
   Py   []byte
}

type Shares struct {
   Data []Share
}

type Secret struct {
    secret.Shamir   
}

// Generate shares from secret
func GenerateShares(secret []byte) {
	// convert secret to right format
	secret_ff, _  := ff.NewElement(PRIME)
	secret_ff.FromByte(secret)
        secret_cfg := GetSecretCfg()
	shares_go, _  := secret_cfg.GenerateShares(secret_ff)
        shares_mobile := GetShares()
        shares_mobile.Data = fromShares(shares_go)
        SetShares(shares_mobile)
}

func toShares(shares *Shares) []secret.Share {
   shares_go := make([]secret.Share, 0)
   secret_config := GetSecretCfg()
   for _, share := range shares.Data {
      new_el, _ := ff.NewElement(secret_config.GetElType())
      new_share_go := secret.Share{ Px : share.Px,
                                    Py : new_el.FromByte(share.Py) }
      shares_go = append(shares_go, new_share_go)
   }

   return shares_go
}

func fromShares(shares []secret.Share) []Share {
        shares_mobile := make([]Share, 0)
        for _, share  := range shares {
            new_share_mobile := Share{  Px : share.Px,
                                        Py : share.Py.ToByte() }
            shares_mobile = append(shares_mobile, new_share_mobile)
        }
        return shares_mobile
}
// Generate secret from shares
func GenerateKey() []byte {
   shares_go := toShares(GetShares())
   return generateKey(shares_go, GetSecretCfg())
}

func generateKey(shares []secret.Share, sharing_cfg secret.SecretSharer) []byte {
	shares_pool := make([]secret.Share, 0)
	for _, share := range shares {
		shares_pool = append(shares_pool, share)
		if len(shares_pool) == sharing_cfg.GetMinShares() {
			break
		}
	}
	secret, err := sharing_cfg.GenerateSecret(shares_pool)
	if err != nil {
		panic(err)
	}

	return secret.ToByte()
}

func InitSecretCfg() {
        var secret_cfg Secret
	err := secret_cfg.NewConfig(MIN_N_SHARES, MAX_N_SHARES, PRIME)
	if err != nil {
		panic(err)
	}
        SetSecretCfg(&secret_cfg)
}

func InitSecretShares() {
    var shares Shares
    share_data := make([]Share, 0)
    shares.Data = share_data
    SetShares(&shares)
}
