package filecrypt

import (
	"encoding/binary"
	"errors"
	"fmt"
)

/*
  Implements Filecrypt Header functionality. Header is added to each encryption block to be able to decrypt it.
  Header size : 16 bytes
  Header Format :
   version                    [ 1 Byte ] :  Header version
   blockIdx                  [ 1 Byte ] :  Indicates type of block (first, middle, last, single)
   fctype                     [ 1 Byte ] :  Module implementing Filecrypt interface
   blocksize                  [ 1 Byte ] :  Encryption block size
   noncesize                  [ 1 Byte ] :  Nonce size in bytes
   lastBlocksize             [ 1 Byte ] :  Size of last block cleartext in bytes
   nblocks                    [ 8 Bytes] :  Number of blocks
*/

// Version (Backwards interop)
const (
	FC_HDR_VERSION_1 = iota
	FC_HDR_NVERSION
)

// block Idx
const (
	FC_HDR_BIDX_FIRST  = iota // first
	FC_HDR_BIDX_MID           // middle
	FC_HDR_BIDX_LAST          // last
	FC_HDR_BIDX_SINGLE        // single
	FC_HDR_NBIDX
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
	FC_HDR_BLOCK_IDX_OFFSET      = 2
	FC_HDR_BSIZE_OFFSET          = 3
	FC_HDR_NONCESIZE_OFFSET      = 4
	FC_HDR_LAST_BLOCKSIZE_OFFSET = 5
	FC_HDR_NBLOCKS_OFFSET        = 6
	FC_HDR_END_OFFSET            = 14
)

// Filecrypt Header added to every FC block
type hdre struct {
	version       int
	blockIdx      int
	fctype        int
	blocksize     int
	noncesize     int
	lastBlocksize int
	nblocks       int
}

// Init Hdr Struct
func (hdr *hdre) FillHdr(Version, Fctype, Blocksize, BlockIdx int) error {
	// check errors
	if Version >= FC_HDR_NVERSION ||
		Fctype >= FC_NTYPE ||
		BlockIdx >= FC_HDR_NBIDX {
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
	hdr.blockIdx = BlockIdx
	hdr.fctype = Fctype
	hdr.blocksize = selKey

	return nil
}

// Add n blocks and padding last block to header
func (hdr *hdre) setNBlocks(nbytes int) {
	hdr.nblocks = int((nbytes + fcBsize[hdr.blocksize] - 1) / fcBsize[hdr.blocksize])
	hdr.lastBlocksize = nbytes % fcBsize[hdr.blocksize]
}

// from bytes to Hdr struct
func (hdr *hdre) fromBytes(hdrBytes []byte) {
	hdr.version = int(hdrBytes[FC_HDR_VERSION_OFFSET])
	hdr.blockIdx = int(hdrBytes[FC_HDR_BLOCK_IDX_OFFSET])
	hdr.fctype = int(hdrBytes[FC_HDR_FCTYPE_OFFSET])
	hdr.blocksize = int(hdrBytes[FC_HDR_BSIZE_OFFSET])
	hdr.noncesize = int(hdrBytes[FC_HDR_NONCESIZE_OFFSET])
	hdr.lastBlocksize = int(hdrBytes[FC_HDR_LAST_BLOCKSIZE_OFFSET])
	hdr.nblocks = int(binary.LittleEndian.Uint64(hdrBytes[FC_HDR_NBLOCKS_OFFSET:FC_HDR_END_OFFSET]))

}

// From HDR struct to bytes
func (hdr hdre) toBytes() ([]byte, error) {
	header := make([]byte, FC_BSIZE_BYTES_128)
	header[FC_HDR_VERSION_OFFSET] = byte(hdr.version)
	header[FC_HDR_BLOCK_IDX_OFFSET] = byte(hdr.blockIdx)
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

func (hdr hdre) getNBlockBytes() int {
	blockBytes := fcBsize[hdr.blocksize] * hdr.nblocks
	if hdr.lastBlocksize > 0 {
		blockBytes -= (fcBsize[hdr.blocksize] - hdr.lastBlocksize)
	}
	return blockBytes
}

func (hdr hdre) isFirstBlock() bool {
	if hdr.blockIdx == FC_HDR_BIDX_FIRST ||
		hdr.blockIdx == FC_HDR_BIDX_SINGLE {
		return true
	}
	return false
}

func (hdr hdre) isLasttBlock() bool {
	if hdr.blockIdx == FC_HDR_BIDX_LAST ||
		hdr.blockIdx == FC_HDR_BIDX_SINGLE {
		return true
	}
	return false
}

func NewHdrEncrypt(Version, Fctype, Blocksize, BlockIdx int) (FileCryptEnc, error) {
	hdr, err := getEncFCFromType(byte(Fctype))
	if err != nil {
		return nil, fmt.Errorf("NewHdrEncrypt : %w", err)
	}
	err = hdr.FillHdr(Version, Fctype, Blocksize, BlockIdx)

	return hdr, err

}

func getEncFCFromType(t byte) (FileCryptEnc, error) {
	var encHdr FileCryptEnc

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
