// Use provided key directly for encryption and decryption without any Key Derivation Fuction

package filecrypt

import (
	"errors"
	"fmt"
	"os"
)

// Implements Direct Key functionality
//  Header size : 2 Bytes
//  Format
//    version    [1 Byte]
//    keytype    [1 Byte]
//    keyIn
//    keyOut

type DirectKeyFc struct {
	version int
	keytype int
	keyIn   []byte
	keyOut  []byte
}

// Hdr format
const (
	FC_DIRECTKEYHDR_END_OFFSET = 2
	FC_DIRECTKEYHDR_NPARMS     = 2
)

// Init Hdr Struct
func (hdr *DirectKeyFc) fillHdr(KeyIn []byte, params ...int) error {
	if len(params) != FC_DIRECTKEYHDR_NPARMS {
		return fmt.Errorf("fillHdr : Incorrect arguments")
	}
	Version := params[0]
	Keytype := params[1]
	// check errors
	if Version >= FC_HDR_NVERSION ||
		Keytype >= FC_KEY_NTYPE {
		return errors.New("Invalid arguments")
	}

	hdr.version = Version
	hdr.keytype = Keytype
	hdr.keyIn = KeyIn
	hdr.keyOut = nil

	return nil
}

// from bytes to Hdr struct
func (hdr *DirectKeyFc) fromBytes(hdrBytes []byte) {
	hdr.version = int(hdrBytes[FC_HDR_VERSION_OFFSET])
	hdr.keytype = int(hdrBytes[FC_HDR_FCTYPE_OFFSET])
	hdr.keyIn = nil
	hdr.keyOut = nil
}

// From HDR struct to bytes
func (hdr DirectKeyFc) toBytes() ([]byte, error) {
	header := make([]byte, FC_DIRECTKEYHDR_END_OFFSET)
	header[FC_HDR_VERSION_OFFSET] = byte(hdr.version)
	header[FC_HDR_FCTYPE_OFFSET] = byte(hdr.keytype)

	return header, nil
}

func (hdr *DirectKeyFc) retrieveKey(keyIn, d []byte, f *os.File) ([]byte, error) {
	return keyIn, nil
}

// Key generation. In Tx, it writes info to a valid fname. In Rx, it reads keyOut
func (hdr *DirectKeyFc) generateKey(fname string) ([]byte, error) {
	// in Tx mode, out key is not available
	if hdr.keyOut == nil {
		// Generate key hdr
		fhdr, err := hdr.toBytes()
		if err != nil {
			return nil, fmt.Errorf("toBytes : %w", err)
		}

		// Write file
		file, err := openFileA(fname)
		if err != nil {
			return nil, fmt.Errorf("Open file : %w", err)
		}
		defer file.Close()

		// write header to file
		_, err = file.Write(fhdr)
		if err != nil {
			return nil, fmt.Errorf("Write file : %w", err)
		}

		hdr.keyOut = hdr.keyIn
	}

	return hdr.keyOut, nil
}
