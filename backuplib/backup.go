// Backup layer

package backuplib

import (
	"fmt"
	fc "github.com/iden3/go-backup/filecrypt"
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
func CreateBackup(keyT, hashT, encT int, fname string) error {
	key := GetkOp()
	// Add Key -> for now, only PBKDF2 + GCM supported, but it can be expanded easily
	//  Assume fixed PBKDF2 config. Header shared for both encrypted and non encrpyted blocks
	hdrK, err := fc.NewHdrKey(key, fc.FC_HDR_VERSION_1, keyT, hashT,
		PBKDF2_NITER, fc.FC_BSIZE_BYTES_256, PBKDF2_SALTLEN)
	if err != nil {
		panic(err)
	}

	nBlocks := len(backupRegistry)
	var blockIdx, bctr = 0, 0

	// There are two types of blcks defined for now:
	// Encrypted -> PBKDF2 Key Header + GCM Enc Header
	// Not Encrypted -> PBKDF2 Key HEader + ClearFC Enc Header
	for _, el := range backupRegistry {
		// Check block index
		if nBlocks == 1 {
			blockIdx = fc.FC_HDR_BIDX_SINGLE
		} else if nBlocks == bctr+1 {
			blockIdx = fc.FC_HDR_BIDX_LAST
		} else if bctr == 0 {
			blockIdx = fc.FC_HDR_BIDX_FIRST
		} else {
			blockIdx = fc.FC_HDR_BIDX_MID
		}

		// Add Enc Header
		fcType := fc.FC_GCM
		if el.mode == DONT_ENCRYPT {
			fcType = fc.FC_CLEAR
		}
		hdrE, _ := fc.NewHdrEncrypt(fc.FC_HDR_VERSION_1, fcType, fc.FC_BSIZE_BYTES_256, blockIdx)
		err = fc.Encrypt(hdrK, hdrE, fname, el.data)
		if err != nil {
			return fmt.Errorf("Encrypt : %w", err)
		}
		bctr += 1
	}
	return nil
}

func initBackup() {
	backupRegistry = make(map[int]Backup)
}
