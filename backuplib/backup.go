// Backup layer

package backuplib

import (
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
var backup_registry map[int]Backup

// Record and register backup data structures
func AddToBackup(t, action int) {
	// check for duplicates
	for idx, _ := range backup_registry {
		if idx == t {
			return
		}
	}
	// encode type
	encodeType(t)

	backup_el := newBackupElement(t, action)
	backup_registry[t] = *backup_el
}

func newBackupElement(t, action int) *Backup {
	switch t {
	case CLAIMS:
		// Add to backup registry
		backup_el := Backup{data: GetBackupClaims(),
			mode: action,
		}
		return &backup_el

	case WALLET_CONFIG:
		backup_el := Backup{data: GetWallet(),
			mode: action,
		}
		return &backup_el

	case ZKP_INFO:
		backup_el := Backup{data: GetZKP(),
			mode: action,
		}
		return &backup_el

	case MERKLE_TREE:
		backup_el := Backup{data: GetMT(),
			mode: action,
		}
		return &backup_el

	case CUSTODIAN:
		backup_el := Backup{data: GetCustodians(),
			mode: action,
		}
		return &backup_el

	case GENID:
		backup_el := Backup{data: GetId(),
			mode: action,
		}
		return &backup_el

	case SSHARING:
		backup_el := Backup{data: GetSecretCfgOriginal(),
			mode: action,
		}
		return &backup_el

	case SHARES:
		backup_el := Backup{data: toShares(GetShares()),
			mode: action,
		}
		return &backup_el

	}
	return nil
}

// Generate backup file
func CreateBackup(key_t, hash_t, enc_t int, fname string) {
	key := GetkOp()
	// Add Key -> for now, only PBKDF2 + GCM supported, but it can be expanded easily
	//  Assume fixed PBKDF2 config. Header shared for both encrypted and non encrpyted blocks
	hdr_k := &fc.Pbkdf2Fc{}
	err := hdr_k.FillHdr(fc.FC_HDR_VERSION_1, key_t, hash_t,
		PBKDF2_NITER, fc.FC_BSIZE_BYTES_256, PBKDF2_SALTLEN, key)
	if err != nil {
		panic(err)
	}

	n_blocks := len(backup_registry)
	var block_idx, bctr = 0, 0

	// There are two types of blcks defined for now:
	// Encrypted -> PBKDF2 Key Header + GCM Enc Header
	// Not Encrypted -> PBKDF2 Key HEader + ClearFC Enc Header
	for _, el := range backup_registry {
		// Check block index
		if n_blocks == 1 {
			block_idx = fc.FC_HDR_BIDX_SINGLE
		} else if n_blocks == bctr+1 {
			block_idx = fc.FC_HDR_BIDX_LAST
		} else if bctr == 0 {
			block_idx = fc.FC_HDR_BIDX_FIRST
		} else {
			block_idx = fc.FC_HDR_BIDX_MID
		}

		// Add Enc Header
		if el.mode == DONT_ENCRYPT {
			hdr_ne := &fc.ClearFc{}
			err = hdr_ne.FillHdr(fc.FC_HDR_VERSION_1, fc.FC_CLEAR, fc.FC_BSIZE_BYTES_256, block_idx)
			err = fc.Encrypt(hdr_k, hdr_ne, fname, el.data)
		} else if el.mode == ENCRYPT {
			hdr_gcm := &fc.GcmFc{}
			err = hdr_gcm.FillHdr(fc.FC_HDR_VERSION_1, fc.FC_GCM, fc.FC_BSIZE_BYTES_256, block_idx)
			err = fc.Encrypt(hdr_k, hdr_gcm, fname, el.data)
		}
		if err != nil {
			panic(err)
		}
		bctr += 1
	}
}

func InitBackup() {
	backup_registry = make(map[int]Backup)
}
