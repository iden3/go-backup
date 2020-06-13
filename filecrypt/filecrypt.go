// Package filecrypt implements filecrypt encryption and decryption protocol
//
// Filecrypt procotol is used to encrypt a set of different data structures
//  into a file that can be exported to a cloud storage site as a backup. It also
//  adds enough information to be able to decrypt it at a later time.
//
// A filecrypt block includes a  Key Header, a encryption header, and a sequence of encrypted blocks.
//   There may be multiple filecrypt blocks with different encryption options. Typically, a filecrypt
//   block includes a data structure. Multiple filecrypt blocks can be appended toguether to encrypt
//   several data structures
//
// Key Header Format -> defined in fckeyhdr.go. It includes information to generate a key from a master
//   key
//  - Version       [1 Byte]
//  - Key Type      [1 Byte]
//  - Key contents  [Variable size] -> Filecrypt supports multiple key derivation protocols, including:
//       - No Key -> nokey.go
//       - Direct -> direct_key.go
//       - PBKDF2 -> pbkdf2dhr.go and and pbkdf2.go
//
//  There is only a single key header per file. All blocks use same key derivation mechanisms
//
//  Encryption Header Format -> defined in hre.go. It includes information to encrypt data. Header
//   it not encrypted. Header is 16 bytes long
//   - Version       [1 Byte]
//   - Block_idx     [1 Byte] Indicates if Filecrypt block is first, midle, last or single
//   - FC type       [1 byte] Indicates how data blocks are encrypted. Methods supported so far:
//         GCM-128, GCM-256 : defined in gcm.go
//         No encryption    : clear.go
//   - Blocksize     [1 byte] Encryption block size (identifier). Currently 128 and 256 bit supported
//   - Noncesize     [1 byte] Size in bytes of nonce (if needed)
//   - Last_blocksize[1 byte] Size in bytes of last cleartext block
//   - nblocks       [8 byte] Number of bytes of cyphertext generated by encryption mechanism
//
//   Every filecrypt block includes a Encryption Header block. It can vary between different filecrypt
//    blocks.
//
//   After the encryption header there are N blocks of encrypted cyphertext

package filecrypt

import (
	"fmt"
	"os"
)

// Interface to describe FileCryptKey operations:
type fileCryptKey interface {
	generateKey(fname string) ([]byte, error)
	retrieveKey(key, d []byte, f *os.File) ([]byte, error)
	toBytes() ([]byte, error)
	fromBytes([]byte)
	fillHdr(KeyIn []byte, Params ...int) error
}

// Interface to describe FileCryptEnc operations:
//   Encrypt : Encrypt cleartext into a filecrypt compatible format file
//   Decrypt : Decrypt a filecrypt file to cleartext
type fileCryptEnc interface {
	decrypt(cyphertext, key []byte) (interface{}, error)
	encrypt(fname string, key []byte, cleartext interface{}) error
	toBytes() ([]byte, error)
	fromBytes([]byte)
	isFirstBlock() bool
	isLasttBlock() bool
	setNBlocks(nbytes int)
	getNBlockBytes() int
	getNoncePaddingLen() int
	setNonceSize(s int)
	fillHdr(Version, Fctype, Blocksize, BlockIdx int) error
}

// KDF Supported Types
const (
	FC_KEY_T_NOKEY  = iota // no Key
	FC_KEY_T_DIRECT        // DIRECT
	FC_KEY_T_PBKDF2        // PBKDF2
	FC_KEY_NTYPE
)

// Filecrypt supported encryption schemes
const (
	FC_CLEAR = iota // No encryption
	FC_GCM          // GCM
	FC_RSA
	FC_NTYPE
)

// Hash Functions
const (
	FC_NOHASH = iota
	FC_HASH_SHA1
	FC_HASH_SHA256
	FC_NHASH
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

// Filecrypt encryption routine. Takes some cleartext and based on the type of encryption
//  applies the desired encryption algorithm.
// Encryption must be called for every filecrypt block that needs to be added to the
// backup file
func Encrypt(keyHdr fileCryptKey, encHdr fileCryptEnc, fname string, cleartext interface{}) error {
	// If first block, generate and write key header
	// else, simply retrieve key
	key, err := keyHdr.generateKey(fname)
	if err != nil {
		return fmt.Errorf("GenerateKey : %w", err)
	}

	// Encrypt block
	err = encHdr.encrypt(fname, key, cleartext)
	if err != nil {
		return fmt.Errorf("Encrypt : %w", err)
	}

	return nil
}

// Filecrypt decryption routine. Takes some cyphertext file and based on the type of decryption
//  specified in the header applies the desired decryption algorithm
// Decrypt is called only once per file and will decrypt the complete file, returning a slice of
// data structures
func Decrypt(fname string, keyIn []byte) ([]interface{}, error) {
	// open file for reading
	file, err := openFileR(fname)
	if err != nil {
		return nil, fmt.Errorf("Open file : %w", err)
	}
	defer file.Close()
	var result []interface{}

	// read Key HDR (2 bytes)
	hdrBytes, err := readNBytesFromFile(file, FC_HDR_FCTYPE_OFFSET+1)
	if err != nil {
		return nil, fmt.Errorf("readNBytesFromFile : %w", err)
	}

	var keyOut []byte
	// check Key HDR Type -> If error, abort
	keyHdr, err := getKeyFCFromType(hdrBytes[FC_HDR_FCTYPE_OFFSET])
	if err != nil {
		return nil, fmt.Errorf("getKeyFCFromType : %w", err)
	}

	keyOut, err = keyHdr.retrieveKey(keyIn, hdrBytes, file)
	for stopDecrypt := false; !stopDecrypt; {
		// read ENC HDR (16B) -> if error abort. We need a valid header
		hdrBytes, err := readNBytesFromFile(file, FC_BSIZE_BYTES_128)
		if err != nil {
			return nil, fmt.Errorf("readNBytesFromFile : %w", err)
		}

		hdr2, err := getEncFCFromType(hdrBytes[FC_HDR_FCTYPE_OFFSET])
		if err != nil {
			return nil, fmt.Errorf("getEncFCFromType : %w", err)
		}

		hdr2.fromBytes(hdrBytes)

		// Check if more blocks after this
		if hdr2.isLasttBlock() {
			stopDecrypt = true
		}

		// read Blocks (with nonce). If error during reading blocks abort
		blockBytes := hdr2.getNBlockBytes()
		blockBuffer, err := readNBytesFromFile(file, blockBytes)
		if err != nil {
			return nil, fmt.Errorf("readNBytesFromFile : %w", err)
		}

		p, err := hdr2.decrypt(blockBuffer, keyOut)
		if err == nil {
			result = append(result, p)
		}

	}
	return result, nil
}
