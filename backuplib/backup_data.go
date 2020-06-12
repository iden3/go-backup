/*
  Backup Data
*/

package backuplib

import (
	"github.com/iden3/go-backup/secret"
	"github.com/iden3/go-iden3-core/db"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

type BackupData struct {
	kOp              []byte         // Key. Assumed it is derived from a password
	wallet           *WalletConfig  // Simulated wallet configuration parameters
	secretShares     *Shares        // Shares. Needed in case we want to continue distributing them
	secretCfg        *secret.Shamir // Configuration osf secret sharing
	secretCustodians *Custodians    // Info on custodians so that we can retrieve it later
	pK               *PrivateKeys   // Identity private keys
	storage          []db.KV        // Identity storage
}

var dataBackup BackupData

// Getters/Setters
func GetkOp() []byte {
	return dataBackup.kOp
}

func SetkOp(kOp []byte) {
	dataBackup.kOp = make([]byte, len(kOp))
	copy(dataBackup.kOp, kOp)
}

func GetWallet() *WalletConfig {
	return dataBackup.wallet
}

func SetWallet(data *WalletConfig) {
	dataBackup.wallet = data
}

func GetShares() *Shares {
	return dataBackup.secretShares
}

func SetShares(data *Shares) {
	dataBackup.secretShares = data
}

func GetSecretCfg() *Secret {
	secretCfg := Secret{
		secret.Shamir{
			MaxShares:   dataBackup.secretCfg.GetMaxShares(),
			MinShares:   dataBackup.secretCfg.GetMinShares(),
			ElementType: dataBackup.secretCfg.GetElType(),
		},
	}
	return &secretCfg
}

func GetSecretCfgOriginal() *secret.Shamir {
	return dataBackup.secretCfg
}

func SetSecretCfg(data *Secret) {
	if data != nil {
		secretCfg := secret.Shamir{
			MaxShares:   data.GetMaxShares(),
			MinShares:   data.GetMinShares(),
			ElementType: data.GetElType(),
		}
		dataBackup.secretCfg = &secretCfg
	} else {
		dataBackup.secretCfg = nil
	}
}

func GetCustodians() *Custodians {
	return dataBackup.secretCustodians
}

func SetCustodians(data *Custodians) {
	dataBackup.secretCustodians = data
}

func GetPrivateKeys() *PrivateKeys {
	return dataBackup.pK
}

func SetPrivateKeys(data *PrivateKeys) {
	if data == nil {
		dataBackup.pK = nil
	} else {
		PK := make([]babyjub.PrivateKey, len(data.PK))
		for idx, pk := range data.PK {
			PK[idx] = pk
		}
		privateKey := PrivateKeys{PK: PK}
		dataBackup.pK = &privateKey
	}
}

func GetStorage() []db.KV {
	return dataBackup.storage
}

func SetStorage(data []db.KV) {
	copy(dataBackup.storage, data)
}

func Init(pass []byte, folder string) {

	// init aux data in backup structure
	SetWallet(initWalletConfig())

	// init Secret Sharing
	initSecretCfg()

	// init Secret Shares
	initSecretShares()

	// init backup registry
	initBackup()

	// init Encoding
	initEncoding()

	// init Custodians
	initCustodians()

	// init identity
	initIdentity(pass, folder)

}
