// Backup layer

package backuplib

import (
	"fmt"
	fc "github.com/iden3/go-backup/filecrypt"
	"strconv"
)

const (
	ENCRYPT = iota
	DONT_ENCRYPT
)

type Backup struct {
	data interface{}
	mode int
}

// Summary of contents of backup file
var backupRegistry map[int]Backup

// Record and register backup data structures
func AddToBackup(t, action int) {
	// check for duplicates
	for idx, _ := range backupRegistry {
		if idx == t {
			return
		}
	}
	backupEl := newBackupElement(t, action)
	backupRegistry[t] = *backupEl
}

func newBackupElement(t, action int) *Backup {
	switch t {

	case WALLET_CONFIG:
		backupEl := Backup{data: GetWallet(),
			mode: action,
		}
		return &backupEl

	case CUSTODIAN:
		backupEl := Backup{data: GetCustodians(),
			mode: action,
		}
		return &backupEl

	case SSHARING:
		backupEl := Backup{data: GetSecretCfgOriginal(),
			mode: action,
		}
		return &backupEl

	case SHARES:
		backupEl := Backup{data: toShares(GetShares()),
			mode: action,
		}
		return &backupEl

	case PKEYS:
		pass := GetkOp()
		_, keystore := id.Export(pass)
		if keystore == nil {
			return nil
		}
		keyStore2PK(keystore, pass)
		backupEl := Backup{data: GetPrivateKeys(),
			mode: action,
		}
		return &backupEl

	case STORAGE:
		pass := GetkOp()
		storage, _ := id.Export(pass)
		if storage == nil {
			return nil
		}
		storage2KV(storage)
		backupEl := Backup{data: GetStorage(),
			mode: action,
		}
		return &backupEl
	}
	return nil
}

// Generate backup file
func CreateBackup(fname string) error {
	key := GetkOp()
	nBlocks := len(backupRegistry)
	fileCrypt, err := fc.New(nBlocks, fname, nil, key, fc.FC_KEY_T_PBKDF2)
	if err != nil {
		return fmt.Errorf("New FC : %w", err)
	}

	// There are two types of blcks defined for now:
	// Encrypted -> PBKDF2 Key Header + GCM Enc Header
	// Not Encrypted -> PBKDF2 Key HEader + ClearFC Enc Header
	for idx, el := range backupRegistry {
		// Add Enc Header
		fcType := fc.FC_GCM
		if el.mode == DONT_ENCRYPT {
			fcType = fc.FC_CLEAR
		}
		tag := strconv.Itoa(idx)
		err := fileCrypt.AddBlock([]byte(tag), fcType, el.data)
		if err != nil {
			return fmt.Errorf("Encrypt : %w", err)
		}
	}
	return nil
}

func initBackup() {
	backupRegistry = make(map[int]Backup)
}
