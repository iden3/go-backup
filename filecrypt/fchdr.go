package filecrypt

import (
	"encoding/binary"
	"errors"
)

/*
  Implements Filecrypt Header functionality. Header is added to each encryption block to be able to decrypt it.
  Header size : 16 bytes
  Header Format :
   version                    [ 1 Byte ] :  Header version
   block_idx                  [ 1 Byte ] :  Indicates type of block (first, middle, last, single)
   fctype                     [ 1 Byte ] :  Module implementing Filecrypt interface
   blocksize                  [ 1 Byte ] :  Encryption block size
   noncesize                  [ 1 Byte ] :  Nonce size in bytes
   last_blocksize             [ 1 Byte ] :  Size of last block cleartext in bytes
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
type fchdr struct {
	version        int
	block_idx      int
	fctype         int
	blocksize      int
	noncesize      int
	last_blocksize int
	nblocks        int
}

// Init Hdr Struct
func (hdr *fchdr) FillHdr(Version, Fctype, Blocksize, Block_idx int) error {
	// check errors
	if Version >= FC_HDR_NVERSION ||
		Fctype >= FC_NTYPE ||
		Block_idx >= FC_HDR_NBIDX {
		return errors.New("Invalid arguments")
	}
	sel_key := FC_HDR_NBSIZE
	for key, val := range fc_bsize {
		if val == Blocksize {
			sel_key = key
			break
		}
	}
	if sel_key == FC_HDR_NBSIZE {
		return errors.New("Invalid arguments")
	}

	hdr.version = Version
	hdr.block_idx = Block_idx
	hdr.fctype = Fctype
	hdr.blocksize = sel_key

	return nil
}

// Add n blocks and padding last block to header
func (hdr *fchdr) setNBlocks(nbytes int) {
	hdr.nblocks = int((nbytes + fc_bsize[hdr.blocksize] - 1) / fc_bsize[hdr.blocksize])
	hdr.last_blocksize = nbytes % fc_bsize[hdr.blocksize]
}

// from bytes to Hdr struct
func (hdr *fchdr) fromBytes(hdr_bytes []byte) {
	hdr.version = int(hdr_bytes[FC_HDR_VERSION_OFFSET])
	hdr.block_idx = int(hdr_bytes[FC_HDR_BLOCK_IDX_OFFSET])
	hdr.fctype = int(hdr_bytes[FC_HDR_FCTYPE_OFFSET])
	hdr.blocksize = int(hdr_bytes[FC_HDR_BSIZE_OFFSET])
	hdr.noncesize = int(hdr_bytes[FC_HDR_NONCESIZE_OFFSET])
	hdr.last_blocksize = int(hdr_bytes[FC_HDR_LAST_BLOCKSIZE_OFFSET])
	hdr.nblocks = int(binary.LittleEndian.Uint64(hdr_bytes[FC_HDR_NBLOCKS_OFFSET:FC_HDR_END_OFFSET]))

}

// From HDR struct to bytes
func (hdr fchdr) toBytes() ([]byte, error) {
	header := make([]byte, FC_BSIZE_BYTES_128)
	header[FC_HDR_VERSION_OFFSET] = byte(hdr.version)
	header[FC_HDR_BLOCK_IDX_OFFSET] = byte(hdr.block_idx)
	header[FC_HDR_FCTYPE_OFFSET] = byte(hdr.fctype)
	header[FC_HDR_BSIZE_OFFSET] = byte(hdr.blocksize)
	header[FC_HDR_NONCESIZE_OFFSET] = byte(hdr.noncesize)
	header[FC_HDR_LAST_BLOCKSIZE_OFFSET] = byte(hdr.last_blocksize)
	binary.LittleEndian.PutUint64(header[FC_HDR_NBLOCKS_OFFSET:FC_HDR_END_OFFSET], uint64(hdr.nblocks))

	return header, nil
}

// returns length of padding added to nonce to fill an integer number of blocks
func (hdr fchdr) getNoncePaddingLen() int {
	nonce_padding := int((hdr.noncesize + fc_bsize[hdr.blocksize] - 1) / fc_bsize[hdr.blocksize] * fc_bsize[hdr.blocksize])
	nonce_padding -= hdr.noncesize
	return nonce_padding
}

func (hdr *fchdr) setNonceSize(s int) {
	hdr.noncesize = s
}

func (hdr fchdr) getNBlockBytes() int {
	block_bytes := fc_bsize[hdr.blocksize] * hdr.nblocks
	if hdr.last_blocksize > 0 {
		block_bytes -= (fc_bsize[hdr.blocksize] - hdr.last_blocksize)
	}
	return block_bytes
}

func (hdr fchdr) isFirstBlock() bool {
	if hdr.block_idx == FC_HDR_BIDX_FIRST ||
		hdr.block_idx == FC_HDR_BIDX_SINGLE {
		return true
	}
	return false
}

func (hdr fchdr) isLasttBlock() bool {
	if hdr.block_idx == FC_HDR_BIDX_LAST ||
		hdr.block_idx == FC_HDR_BIDX_SINGLE {
		return true
	}
	return false
}
