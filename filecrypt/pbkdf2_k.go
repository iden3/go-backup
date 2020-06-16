package filecrypt

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"os"
)

/*
  Implements PBKDF2 Header functionality. Header is added to each encryption block to be able to decrypt it.
  Header size : variable
  Header Format :
   version                    [ 1 Byte ] :  Header version
   keytype                    [ 1 Byte ] :
   hdrlen                     [ 1 Byte ] :
   hash                       [ 1 Byte ] :
   iter                       [ 4 Byte ] :
   outlen                     [ 1 Byte ] :
   saltlen                    [ 1 Byte ] :
   salt                       [ 1 Byte ] :
   keyIn
   keyOut
*/

const (
	FC_PBKDF2HDR_MAXITER     = 100000
	FC_PBKDF2HDR_SALT_MAXLEN = 128
	FC_PBKDF2HDR_OUT_MAXLEN  = 128
	FC_PBKDF2HDR_MINPARAMS   = 2
	FC_PBKDF2HDR_MAXPARAMS   = 6
)

// Hdr format
const (
	FC_PBKDF2HDR_LEN_OFFSET     = 2
	FC_PBKDF2HDR_HASH_OFFSET    = 3
	FC_PBKDF2HDR_ITER_OFFSET    = 4
	FC_PBKDF2HDR_OUTLEN_OFFSET  = 8
	FC_PBKDF2HDR_SALTLEN_OFFSET = 9
	FC_PBKDF2HDR_SALT_OFFSET    = 10
)

const (
	FC_PBKDF2HDR_DEF_HASH    = FC_HASH_SHA256
	FC_PBKDF2HDR_DEF_NITER   = 60000
	FC_PBKDF2HDR_DEF_OUTLEN  = FC_BSIZE_BYTES_256
	FC_PBKDF2HDR_DEF_SALTLEN = 12
)

// Filecrypt Header added to every FC block
type Pbkdf2Fc struct {
	version  int
	keytype  int
	hdrlen   int
	hashtype int
	iter     int
	outlen   int
	saltlen  int
	salt     []byte
	keyIn    []byte
	keyOut   []byte
}

// Init Hdr Struct
func (hdr *Pbkdf2Fc) fillHdr(KeyIn []byte, params ...int) error {
	if len(params) < FC_PBKDF2HDR_MINPARAMS || len(params) > FC_PBKDF2HDR_MAXPARAMS {
		return fmt.Errorf("fillHdr : Incorrect arguments")
	}
	Version := params[0]
	Keytype := params[1]
	Hashtype := FC_PBKDF2HDR_DEF_HASH
	if len(params) > 2 {
		Hashtype = params[2]
	}
	Iter := FC_PBKDF2HDR_DEF_NITER
	if len(params) > 3 {
		Iter = params[3]
	}
	Outlen := FC_PBKDF2HDR_DEF_OUTLEN
	if len(params) > 4 {
		Outlen = params[4]
	}
	Saltlen := FC_PBKDF2HDR_DEF_SALTLEN
	if len(params) > 5 {
		Saltlen = params[5]
	}

	// check errors
	if Version >= FC_HDR_NVERSION ||
		Keytype >= FC_KEY_NTYPE ||
		Iter >= FC_PBKDF2HDR_MAXITER ||
		Outlen >= FC_PBKDF2HDR_OUT_MAXLEN ||
		Hashtype >= FC_NHASH ||
		Saltlen >= FC_PBKDF2HDR_SALT_MAXLEN {
		return errors.New("Invalid arguments")
	}

	hdr.version = Version
	hdr.keytype = Keytype
	hdr.hdrlen = FC_PBKDF2HDR_SALT_OFFSET + Saltlen
	hdr.hashtype = Hashtype
	hdr.iter = Iter
	hdr.outlen = Outlen
	hdr.saltlen = Saltlen
	hdr.salt, _ = genRandomBytes(hdr.saltlen)
	hdr.keyIn = KeyIn
	hdr.keyOut = nil

	return nil
}

// from bytes to Hdr struct
func (hdr *Pbkdf2Fc) fromBytes(hdrBytes []byte) {
	hdr.version = int(hdrBytes[FC_HDR_VERSION_OFFSET])
	hdr.keytype = int(hdrBytes[FC_HDR_FCTYPE_OFFSET])
	hdr.hdrlen = int(hdrBytes[FC_PBKDF2HDR_LEN_OFFSET])
	hdr.hashtype = int(hdrBytes[FC_PBKDF2HDR_HASH_OFFSET])
	hdr.iter = int(binary.LittleEndian.Uint32(hdrBytes[FC_PBKDF2HDR_ITER_OFFSET:FC_PBKDF2HDR_OUTLEN_OFFSET]))
	hdr.outlen = int(hdrBytes[FC_PBKDF2HDR_OUTLEN_OFFSET])
	hdr.saltlen = int(hdrBytes[FC_PBKDF2HDR_SALTLEN_OFFSET])
	hdr.salt = hdrBytes[FC_PBKDF2HDR_SALT_OFFSET : FC_PBKDF2HDR_SALT_OFFSET+hdr.saltlen]
	hdr.keyIn = nil
	hdr.keyOut = nil
}

// From HDR struct to bytes
func (hdr Pbkdf2Fc) toBytes() ([]byte, error) {
	if hdr.hdrlen != FC_PBKDF2HDR_SALT_OFFSET+hdr.saltlen {
		return nil, errors.New("Malformed PBKDF2 struct")
	}
	header := make([]byte, hdr.hdrlen)
	header[FC_HDR_VERSION_OFFSET] = byte(hdr.version)
	header[FC_HDR_FCTYPE_OFFSET] = byte(hdr.keytype)
	header[FC_PBKDF2HDR_LEN_OFFSET] = byte(hdr.hdrlen)
	header[FC_PBKDF2HDR_HASH_OFFSET] = byte(hdr.hashtype)
	binary.LittleEndian.PutUint32(header[FC_PBKDF2HDR_ITER_OFFSET:FC_PBKDF2HDR_OUTLEN_OFFSET], uint32(hdr.iter))
	header[FC_PBKDF2HDR_OUTLEN_OFFSET] = byte(hdr.outlen)
	header[FC_PBKDF2HDR_SALTLEN_OFFSET] = byte(hdr.saltlen)
	copy(header[FC_PBKDF2HDR_SALT_OFFSET:FC_PBKDF2HDR_SALT_OFFSET+hdr.saltlen], hdr.salt)

	return header, nil
}

func (hdr *Pbkdf2Fc) retrieveKey(keyIn, prevHhdr []byte, file *os.File) ([]byte, error) {

	pbkdf2Len, err := readNBytesFromFile(file, 1)
	if err != nil {
		return nil, fmt.Errorf("readNBytesFromFile : %w", err)
	}

	// Read Remaining Hdr (discount version type and length read earlier from length)
	pbkdf2Rem, err := readNBytesFromFile(file, int(pbkdf2Len[0])-FC_PBKDF2HDR_LEN_OFFSET-1)
	if err != nil {
		return nil, fmt.Errorf("readNBytesFromFile : %w", err)
	}

	// Reassemble HDR
	var pbkdf2Byte []byte
	pbkdf2Byte = append(pbkdf2Byte, prevHhdr...)
	pbkdf2Byte = append(pbkdf2Byte, pbkdf2Len...)
	pbkdf2Byte = append(pbkdf2Byte, pbkdf2Rem...)

	hdr.fromBytes(pbkdf2Byte)
	hdr.keyIn = keyIn
	err = hdr.computeKey()

	return hdr.keyOut, nil
}

func (hdr *Pbkdf2Fc) generateKey(fname string) ([]byte, error) {
	// in Tx mode, out key is not available
	if hdr.keyOut == nil {
		// generate header
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

		// compute Key
		err = hdr.computeKey()
		if err != nil {
			return nil, fmt.Errorf("Compute Key : %w", err)
		}
	}

	return hdr.keyOut, nil
}

func (hdr *Pbkdf2Fc) computeKey() error {
	switch hdr.hashtype {
	case FC_HASH_SHA256:
		hdr.keyOut = pbkdf2.Key(hdr.keyIn, hdr.salt, hdr.iter, hdr.outlen, sha256.New)

	default:
		return errors.New("Hash not implemented")
	}

	return nil
}
