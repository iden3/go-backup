package filecrypt

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"os"
	//"encoding/binary"
	//"crypto/rand"
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
   key_in
   key_out
*/

const (
	FC_PBKDF2HDR_MAXITER     = 100000
	FC_PBKDF2HDR_SALT_MAXLEN = 128
	FC_PBKDF2HDR_OUT_MAXLEN  = 128
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
	key_in   []byte
	key_out  []byte
}

// Init Hdr Struct
func (hdr *Pbkdf2Fc) FillHdr(Version, Keytype, Hashtype, Iter, Outlen, Saltlen int, Key_in []byte) error {
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
	hdr.key_in = Key_in
	hdr.key_out = nil

	return nil
}

// from bytes to Hdr struct
func (hdr *Pbkdf2Fc) fromBytes(hdr_bytes []byte) {
	hdr.version = int(hdr_bytes[FC_HDR_VERSION_OFFSET])
	hdr.keytype = int(hdr_bytes[FC_HDR_FCTYPE_OFFSET])
	hdr.hdrlen = int(hdr_bytes[FC_PBKDF2HDR_LEN_OFFSET])
	hdr.hashtype = int(hdr_bytes[FC_PBKDF2HDR_HASH_OFFSET])
	hdr.iter = int(binary.LittleEndian.Uint32(hdr_bytes[FC_PBKDF2HDR_ITER_OFFSET:FC_PBKDF2HDR_OUTLEN_OFFSET]))
	hdr.outlen = int(hdr_bytes[FC_PBKDF2HDR_OUTLEN_OFFSET])
	hdr.saltlen = int(hdr_bytes[FC_PBKDF2HDR_SALTLEN_OFFSET])
	hdr.salt = hdr_bytes[FC_PBKDF2HDR_SALT_OFFSET : FC_PBKDF2HDR_SALT_OFFSET+hdr.saltlen]
	hdr.key_in = nil
	hdr.key_out = nil
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

func (hdr *Pbkdf2Fc) retrieveKey(key_in, prev_hdr []byte, file *os.File) ([]byte, error) {

	pbkdf2_len, err := readNBytesFromFile(file, 1)
	checkError(err)

	// Read Remaining Hdr (discount version type and length read earlier from length)
	pbkdf2_rem, err := readNBytesFromFile(file, int(pbkdf2_len[0])-FC_PBKDF2HDR_LEN_OFFSET-1)
	checkError(err)

	// Reassemble HDR
	var pbkdf2_byte []byte
	pbkdf2_byte = append(pbkdf2_byte, prev_hdr...)
	pbkdf2_byte = append(pbkdf2_byte, pbkdf2_len...)
	pbkdf2_byte = append(pbkdf2_byte, pbkdf2_rem...)

	hdr.fromBytes(pbkdf2_byte)
	hdr.key_in = key_in
	err = hdr.computeKey()

	return hdr.key_out, nil
}

func (hdr *Pbkdf2Fc) generateKey(fname string) ([]byte, error) {
	// in Tx mode, out key is not available
	if hdr.key_out == nil {
		// generate header
		fhdr, err := hdr.toBytes()
		checkError(err)

		// Create file
		file, err := openFileW(fname)
		checkError(err)
		defer file.Close()

		// write header to file
		_, err = file.Write(fhdr)
		checkError(err)

		// compute Key
		err = hdr.computeKey()
		checkError(err)
	}

	return hdr.key_out, nil
}

func (hdr *Pbkdf2Fc) computeKey() error {
	switch hdr.hashtype {
	case FC_HASH_SHA1:
		hdr.key_out = pbkdf2.Key(hdr.key_in, hdr.salt, hdr.iter, hdr.outlen, sha1.New)

	case FC_HASH_SHA256:
		hdr.key_out = pbkdf2.Key(hdr.key_in, hdr.salt, hdr.iter, hdr.outlen, sha256.New)

	default:
		return errors.New("Hash not implemented")
	}

	return nil
}
