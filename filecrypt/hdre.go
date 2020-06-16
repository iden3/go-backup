package filecrypt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

/*
  Implements Filecrypt Header functionality. Header is added to each encryption block to be able to decrypt it.
  Header size : 16 bytes
  Header Format :
   version                    [ 1 Byte ] :  Header version
   fctype                     [ 1 Byte ] :  Module implementing Filecrypt interface
   blocksize                  [ 1 Byte ] :  Encryption block size
   noncesize                  [ 1 Byte ] :  Nonce size in bytes
   lastBlocksize             [ 1 Byte ] :  Size of last block cleartext in bytes
   nblocks                    [ 8 Bytes] :  Number of blocks
*/

// Filecrypt supported encryption schemes
const (
	FC_CLEAR = iota // No encryption
	FC_GCM          // GCM
	FC_RSA
	FC_NTYPE
)

// Supported encryption block sizes in bytes
const (
	FC_BSIZE_BYTES_128  = 16
	FC_BSIZE_BYTES_256  = 32
	FC_BSIZE_BYTES_2048 = 256
	FC_BSIZE_BYTES_4096 = 512
)

var fcBsize map[int]int = map[int]int{
	FC_HDR_BSIZE_128:  FC_BSIZE_BYTES_128,
	FC_HDR_BSIZE_256:  FC_BSIZE_BYTES_256,
	FC_HDR_BSIZE_2048: FC_BSIZE_BYTES_2048,
	FC_HDR_BSIZE_4096: FC_BSIZE_BYTES_4096,
}

// Version (Backwards interop)
const (
	FC_HDRE_VERSION_1 = iota
	FC_HDRE_NVERSION
)

const (
	FC_HDRE_DEF_VERSION = FC_HDRE_VERSION_1
)

// block size
const (
	FC_HDR_BSIZE_128 = iota
	FC_HDR_BSIZE_256
	FC_HDR_BSIZE_2048
	FC_HDR_BSIZE_4096
	FC_HDR_NBSIZE
)

// Hdr format
const (
	FC_HDR_VERSION_OFFSET        = 0
	FC_HDR_FCTYPE_OFFSET         = 1
	FC_HDR_BSIZE_OFFSET          = 2
	FC_HDR_NONCESIZE_OFFSET      = 3
	FC_HDR_LAST_BLOCKSIZE_OFFSET = 4
	FC_HDR_NBLOCKS_OFFSET        = 5
	FC_HDR_END_OFFSET            = 13
)

// Filecrypt Header added to every FC block
type hdre struct {
	version       int
	fctype        int
	blocksize     int
	noncesize     int
	lastBlocksize int
	nblocks       int64
}

// Init Hdr Struct
func (hdr *hdre) fillHdr(Version, Fctype, Blocksize int) error {
	// check errors
	if Version >= FC_HDR_NVERSION ||
		Fctype >= FC_NTYPE {
		return errors.New("Invalid arguments")
	}
	selKey := FC_HDR_NBSIZE
	for key, val := range fcBsize {
		if val == Blocksize {
			selKey = key
			break
		}
	}
	if selKey == FC_HDR_NBSIZE {
		return errors.New("Invalid arguments")
	}

	hdr.version = Version
	hdr.fctype = Fctype
	hdr.blocksize = selKey

	return nil
}

// Add n blocks and padding last block to header
func (hdr *hdre) setNBlocks(nbytes int64) {
	bSize := int64(fcBsize[hdr.blocksize])
	hdr.nblocks = (nbytes + bSize - int64(1)) / bSize
	hdr.lastBlocksize = int(nbytes % bSize)
}

// from bytes to Hdr struct
func (hdr *hdre) fromBytes(hdrBytes []byte) {
	hdr.version = int(hdrBytes[FC_HDR_VERSION_OFFSET])
	hdr.fctype = int(hdrBytes[FC_HDR_FCTYPE_OFFSET])
	hdr.blocksize = int(hdrBytes[FC_HDR_BSIZE_OFFSET])
	hdr.noncesize = int(hdrBytes[FC_HDR_NONCESIZE_OFFSET])
	hdr.lastBlocksize = int(hdrBytes[FC_HDR_LAST_BLOCKSIZE_OFFSET])
	hdr.nblocks = int64(binary.LittleEndian.Uint64(hdrBytes[FC_HDR_NBLOCKS_OFFSET:FC_HDR_END_OFFSET]))

}

// From HDR struct to bytes
func (hdr hdre) toBytes() ([]byte, error) {
	header := make([]byte, FC_BSIZE_BYTES_128)
	header[FC_HDR_VERSION_OFFSET] = byte(hdr.version)
	header[FC_HDR_FCTYPE_OFFSET] = byte(hdr.fctype)
	header[FC_HDR_BSIZE_OFFSET] = byte(hdr.blocksize)
	header[FC_HDR_NONCESIZE_OFFSET] = byte(hdr.noncesize)
	header[FC_HDR_LAST_BLOCKSIZE_OFFSET] = byte(hdr.lastBlocksize)
	binary.LittleEndian.PutUint64(header[FC_HDR_NBLOCKS_OFFSET:FC_HDR_END_OFFSET], uint64(hdr.nblocks))

	return header, nil
}

// returns length of padding added to nonce to fill an integer number of blocks
func (hdr hdre) getNoncePaddingLen() int {
	noncePadding := int((hdr.noncesize + fcBsize[hdr.blocksize] - 1) / fcBsize[hdr.blocksize] * fcBsize[hdr.blocksize])
	noncePadding -= hdr.noncesize
	return noncePadding
}

func (hdr *hdre) setNonceSize(s int) {
	hdr.noncesize = s
}

func (hdr hdre) getNBlockBytes() int64 {
	blockBytes := int64(fcBsize[hdr.blocksize]) * hdr.nblocks
	if hdr.lastBlocksize > 0 {
		blockBytes -= int64(fcBsize[hdr.blocksize] - hdr.lastBlocksize)
	}
	return blockBytes
}

func newHdrEncryptFromFile(file *os.File) (fileCryptEnc, error) {
	// read ENC HDR (16B) -> if error abort. We need a valid header
	hdrBytes, err := readNBytesFromFile(file, FC_BSIZE_BYTES_128)
	if err != nil {
		return nil, fmt.Errorf("readNBytesFromFile : %w", err)
	}

	hdrE, err := getEncFCFromType(hdrBytes[FC_HDR_FCTYPE_OFFSET])
	if err != nil {
		return nil, fmt.Errorf("getEncFCFromType : %w", err)
	}

	hdrE.fromBytes(hdrBytes)

	return hdrE, nil
}

func NewHdrEncrypt(Version, Fctype, Blocksize int) (fileCryptEnc, error) {
	hdr, err := getEncFCFromType(byte(Fctype))
	if err != nil {
		return nil, fmt.Errorf("NewHdrEncrypt : %w", err)
	}
	err = hdr.fillHdr(Version, Fctype, Blocksize)

	return hdr, err

}

func getEncFCFromType(t byte) (fileCryptEnc, error) {
	var encHdr fileCryptEnc

	switch t {
	case FC_CLEAR:
		encHdr = &ClearFc{}

	case FC_GCM:
		encHdr = &GcmFc{}

	case FC_RSA:
		encHdr = &RsaFc{}

	default:
		return nil, errors.New("Incorrect Filecrypt handler type")
	}

	return encHdr, nil
}

func decryptBlock(file *os.File, offset int64, key []byte) (interface{}, error) {
	// Set correct position
	_, err := file.Seek(offset, 0)
	if err != nil {
		return nil, fmt.Errorf("Seek file : %w", err)
	}
	// initialize Encryption Hdr
	hdrE, err := newHdrEncryptFromFile(file)
	if err != nil {
		return nil, fmt.Errorf("newHdrEncryptFromFile : %w", err)
	}

	// read Blocks (with nonce). If error during reading blocks abort
	blockBytes := hdrE.getNBlockBytes()
	blockBuffer, err := readNBytesFromFile(file, int(blockBytes))
	if err != nil {
		return nil, fmt.Errorf("readNBytesFromFile : %w", err)
	}

	return hdrE.decrypt(blockBuffer, key)
}
