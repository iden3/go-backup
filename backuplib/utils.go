/* Aux functions to initialize claim, mk, zkp wallet config data.
*  It also includes very simplified functionality from other modules that should be part of backup package
     but are still not implemented, like custodians, ....

*/

package backuplib

import (
	crand "crypto/rand"
	"github.com/iden3/go-backup/ff"
	fc "github.com/iden3/go-backup/filecrypt"
	"github.com/iden3/go-backup/secret"
	"io"
	"reflect"
)

// Configuration constants
const (
	N_ELEMENTS     = 1000
	ID_LEN         = 31
	MIN_N_SHARES   = 4
	MAX_N_SHARES   = 10
	PRIME          = ff.FF_BN256_PRIME
	BACKUP_DIR     = "../testdata/"
	BACKUP_FILE    = "../testdata/backup.bk"
	QR_DIR         = "../testdata/"
	PBKDF2_NITER   = 60000
	PBKDF2_SALTLEN = 12
	PBKDF2_KEY     = fc.FC_KEY_T_PBKDF2
	SHA256_HASH    = fc.FC_HASH_SHA256
	GCM_ENCRYPTION = fc.FC_GCM
)

type BackupData struct {
	iD               []byte
	kOp              []byte
	Wallet           *WalletConfig
	Claims           *Claim
	ZKPData          *ZKP
	MerkleTree       *MT
	SecretShares     *Shares
	Secret_cfg       *secret.Shamir
	SecretCustodians *Custodians
}

var DataBackup BackupData

func GetId() []byte {
	return DataBackup.iD
}

func SetId(iD []byte) {
	DataBackup.iD = make([]byte, len(iD))
	copy(DataBackup.iD, iD)
}

func GetkOp() []byte {
	return DataBackup.kOp
}

func SetkOp(kOp []byte) {
	DataBackup.kOp = make([]byte, len(kOp))
	copy(DataBackup.kOp, kOp)
}

func GetWallet() *WalletConfig {
	return DataBackup.Wallet
}

func SetWallet(data *WalletConfig) {
	DataBackup.Wallet = data
}

func GetBackupClaims() *Claim {
	return DataBackup.Claims
}

func SetBackupClaims(data *Claim) {
	DataBackup.Claims = data
}

func GetZKP() *ZKP {
	return DataBackup.ZKPData
}

func SetZKP(data *ZKP) {
	DataBackup.ZKPData = data
}

func GetMT() *MT {
	return DataBackup.MerkleTree
}

func SetMT(data *MT) {
	DataBackup.MerkleTree = data
}

func GetShares() *Shares {
	return DataBackup.SecretShares
}

func SetShares(data *Shares) {
	DataBackup.SecretShares = data
}

//func GetSecretCfg()  *secret.Shamir {
func GetSecretCfg() *Secret {
	secret_cfg := Secret{
		secret.Shamir{
			Max_shares:   DataBackup.Secret_cfg.GetMaxShares(),
			Min_shares:   DataBackup.Secret_cfg.GetMinShares(),
			Element_type: DataBackup.Secret_cfg.GetElType(),
		},
	}
	return &secret_cfg
}
func GetSecretCfgOriginal() *secret.Shamir {
	return DataBackup.Secret_cfg
}

//func SetSecretCfg(data *secret.Shamir) {
func SetSecretCfg(data *Secret) {
	if data != nil {
		secret_cfg := secret.Shamir{
			Max_shares:   data.GetMaxShares(),
			Min_shares:   data.GetMinShares(),
			Element_type: data.GetElType(),
		}
		DataBackup.Secret_cfg = &secret_cfg
	} else {
		DataBackup.Secret_cfg = nil
	}
}

func GetCustodians() *Custodians {
	return DataBackup.SecretCustodians
}

func SetCustodians(data *Custodians) {
	DataBackup.SecretCustodians = data
}

////
func init() {
	Init()
}

func Init() {
	//init aux data
	Claims = initClaims()
	ZKPData = initZKP()
	MerkleTree = initMerkleTree()

	// init aux data in backup structure
	SetBackupClaims(Claims)
	SetWallet(initWalletConfig())
	SetZKP(ZKPData)
	SetMT(MerkleTree)

	// init Secret Sharing
	InitSecretCfg()

	// init Secret Shares
	InitSecretShares()

	// init backup registry
	InitBackup()

	// init Encoding
	InitEncoding()

	// init Custodians
	InitCustodians()
}
func CheckEqual(expected, obtained interface{}) bool {
	flag := false

	switch obtained.(type) {
	case []map[uint64]ff.Element:
		o := obtained.([]map[uint64]ff.Element)
		flag = reflect.DeepEqual(expected, o[0])

	default:
		flag = reflect.DeepEqual(expected, obtained)
	}
	return flag
}

func genRandomBytes(noncesize int) ([]byte, error) {
	nonce := make([]byte, noncesize)
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}
