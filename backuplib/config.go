/*
   Configuration parameters
*/

package backuplib

import (
	"github.com/iden3/go-backup/ff"
	fc "github.com/iden3/go-backup/filecrypt"
)

// Configuration constants
const (
	N_ELEMENTS            = 1000 // used by walletcfg currently
	MIN_N_SHARES          = 4
	MAX_N_SHARES          = 10
	PRIME                 = ff.FF_BN256_FP
	BACKUP_FILE           = "../testdata/backup.bk"
	QR_DIR                = "../testdata/"
	PBKDF2_NITER          = 60000
	PBKDF2_SALTLEN        = 12
	PBKDF2_KEY            = fc.FC_KEY_T_PBKDF2
	SHA256_HASH           = fc.FC_HASH_SHA256
	GCM_ENCRYPTION        = fc.FC_GCM
	WEB3URL               = "https://foo.bar"
	HOLDER_TICKET_PERIOD  = 1000
	IDENTITY_MAIN_STORAGE = "identityTest"
	FOLDER_STORE          = "store"
	FOLDER_KSTORE         = "keystore"
	KSTORE_FILE           = "/idKeyStore"
	STORE_FILE            = "/idStore"
)

type config struct {
	Web3Url            string `yaml:"web3Url"`
	HolderTicketPeriod int    `yaml:"holderTicketPeriod"`
}

var c config
