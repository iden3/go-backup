package filecrypt

import (
	"fmt"
	"os"
)

// KDF Supported Types
const (
	FC_KEY_T_NOKEY  = iota // no Key
	FC_KEY_T_DIRECT        // DIRECT
	FC_KEY_T_PBKDF2        // PBKDF2
	FC_KEY_NTYPE
)

// Version (Backwards interop)
const (
	FC_HDRK_VERSION_1 = iota
	FC_HDREK_NVERSION
)

const (
	FC_HDRK_DEF_VERSION = FC_HDRK_VERSION_1
)

func retrieveKey(file *os.File, offset int64, keyIn []byte) ([]byte, error) {
	// Set correct position
	_, err := file.Seek(offset, 0)
	if err != nil {
		return nil, fmt.Errorf("Seek file : %w", err)
	}
	// read Key HDR (2 bytes)
	hdrBytes, err := readNBytesFromFile(file, FC_HDR_FCTYPE_OFFSET+1)
	if err != nil {
		return nil, fmt.Errorf("readNBytesFromFile : %w", err)
	}

	// check Key HDR Type -> If error, abort
	keyHdr, err := getKeyFCFromType(hdrBytes[FC_HDR_FCTYPE_OFFSET])
	if err != nil {
		return nil, fmt.Errorf("getKeyFCFromType : %w", err)
	}

	return keyHdr.retrieveKey(keyIn, hdrBytes, file)
}

func NewHdrKey(KeyIn []byte, params ...int) (fileCryptKey, error) {
	if len(params) < 2 {
		return nil, fmt.Errorf("NewHdrKey : Incorrect params")
	}
	hdr, err := getKeyFCFromType(byte(params[1]))
	if err != nil {
		return nil, fmt.Errorf("getKeyFCFromType : %w", err)
	}
	err = hdr.fillHdr(KeyIn, params...)

	return hdr, err
}
func getKeyFCFromType(t byte) (fileCryptKey, error) {
	// check Key HDR Type
	var keyHdr fileCryptKey
	switch t {
	case FC_KEY_T_NOKEY:
		keyHdr = &NoKeyFc{}

	case FC_KEY_T_DIRECT:
		keyHdr = &DirectKeyFc{}

	case FC_KEY_T_PBKDF2:
		keyHdr = &Pbkdf2Fc{}

	default:
		return nil, fmt.Errorf("Invalid Key Header")
	}
	return keyHdr, nil
}
