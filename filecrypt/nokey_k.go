package filecrypt

import (
	"errors"
	"fmt"
	"os"
)

// Implements No Key functionality
//  Header size : 2 Bytes
//  Format
//    version [1 Byte]
//    type    [1 Byte]

type NoKeyFc struct {
	version int
	keytype int
	keyIn   []byte
	keyOut  []byte
}

// Hdr format
const (
	FC_NOKEYHDR_END_OFFSET = 2
	FC_NOKEYHDR_NPARAMS    = 2
)

// Init Hdr Struct
func (hdr *NoKeyFc) fillHdr(KeyIn []byte, params ...int) error {
	if len(params) != FC_NOKEYHDR_NPARAMS {
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
	hdr.keyIn = nil
	hdr.keyOut = nil

	return nil
}

// from bytes to Hdr struct
func (hdr *NoKeyFc) fromBytes(hdrBytes []byte) {
	hdr.version = int(hdrBytes[FC_HDR_VERSION_OFFSET])
	hdr.keytype = int(hdrBytes[FC_HDR_FCTYPE_OFFSET])
	hdr.keyIn = nil
	hdr.keyOut = nil
}

// From HDR struct to bytes
func (hdr NoKeyFc) toBytes() ([]byte, error) {
	header := make([]byte, FC_NOKEYHDR_END_OFFSET)
	header[FC_HDR_VERSION_OFFSET] = byte(hdr.version)
	header[FC_HDR_FCTYPE_OFFSET] = byte(hdr.keytype)

	return header, nil
}

func (hdr *NoKeyFc) retrieveKey(keyIn, d []byte, f *os.File) ([]byte, error) {
	return nil, nil
}

func (hdr *NoKeyFc) generateKey(fname string) ([]byte, error) {
	// in Tx mode, out key is not available
	if hdr.keyOut == nil {
		// Generate key
		fhdr, err := hdr.toBytes()
		if err != nil {
			return nil, fmt.Errorf("toBytes : %w", err)
		}

		// Open file
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

		hdr.keyOut = make([]byte, 1)
	}

	return nil, nil
}
