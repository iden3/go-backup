package filecrypt

import (
	"fmt"
)

func NewHdrKey(KeyIn []byte, params ...int) (FileCryptKey, error) {
	if len(params) < 2 {
		return nil, fmt.Errorf("NewHdrKey : Incorrect params")
	}
	hdr, err := getKeyFCFromType(byte(params[1]))
	if err != nil {
		return nil, fmt.Errorf("getKeyFCFromType : %w", err)
	}
	err = hdr.FillHdr(KeyIn, params...)

	return hdr, err
}
func getKeyFCFromType(t byte) (FileCryptKey, error) {
	// check Key HDR Type
	var keyHdr FileCryptKey
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
