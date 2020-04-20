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
//  Encryption Header Format -> defined in fchdr.go. It includes information to encrypt data. Header
//   it not encrypted. Header is 16 bytes long
//   - Version       [1 Byte]
//   - Block_idx     [1 Byte] Indicates if Filecrypt block is first, midle, last or single
//   - FC type       [1 byte] Indicates how data blocks are encrypted. Methods supported so far:
//         GCM-128, GCM-256 : defined in gcm.go 
//         No encryption    : clear.go
//   - Blocksize     [1 byte] Encryption block size (identifier). Currently 128 and 256 bit supported
//   - Noncesize     [1 byte] Size in bytes of nonce (if needed)
//   - Last_blocksize[1 byte] Size in bytes of last cleartext block
//   - nblocks       [1 byte] Number of bytes of cyphertext generated by encryption mechanism
//
//   Every filecrypt block includes a Encryption Header block. It can vary between different filecrypt
//    blocks.
//
//   After the encryption header there are N blocks of encrypted cyphertext

package filecrypt

import (
        "errors"
        "os"
)

// Interface to describe Filecrypter operations:
//   Encrypt : Encrypt cleartext into a filecrypt compatible format file
//   Decrypt : Decrypt a filecrypt file to cleartext
type fileCryptKey interface {
   generateKey(fname string) ([]byte, error)
   retrieveKey(key, d []byte, f *os.File) ([]byte, error)
}

type fileCryptEnc interface {
   decrypt(cyphertext, key []byte) (interface{}, error)
   encrypt(fname string, key []byte, cleartext interface{}) error
   fromBytes([]byte)
   isLasttBlock() bool
   getNBlockBytes() int
}

// KDF Supported Types
const (
       FC_KEY_T_NOKEY = iota   // no Key
       FC_KEY_T_DIRECT         // DIRECT
       FC_KEY_T_PBKDF2         // PBKDF2
       FC_KEY_NTYPE
)

// Filecrypt supported encryption schemes 
const (
        FC_CLEAR = iota   // No encryption
        FC_GCM            // GCM
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
       FC_BSIZE_BYTES_128 =  16
       FC_BSIZE_BYTES_256 =  32
)

var fc_bsize  map[int]int = map[int]int {
       FC_HDR_BSIZE_128 : FC_BSIZE_BYTES_128,
       FC_HDR_BSIZE_256 : FC_BSIZE_BYTES_256,
}


// Filecrypt encryption routine. Takes some cleartext and based on the type of encryption 
//  applies the desired encryption algorithm.
// Encryption must be called for every filecrypt block that needs to be added to the 
// backup file
func   Encrypt(key_hdr fileCryptKey, enc_hdr fileCryptEnc, fname string, cleartext interface{}) error {
   // If first block, generate and write key header
   // else, simply retrieve key
   key, err := key_hdr.generateKey(fname) 
   checkError(err)

   // Encrypt block
   err = enc_hdr.encrypt(fname, key, cleartext)

   return err
}


// Filecrypt decryption routine. Takes some cyphertext file and based on the type of decryption 
//  specified in the header applies the desired decryption algorithm
// Decrypt is called only once per file and will decrypt the complete file, returning a slice of
// data structures
func   Decrypt(fname string, key_in []byte) ([]interface{}, error) {
   // open file for reading
   file, err := openFileR(fname)
   checkError(err)
   defer file.Close()
   var result []interface{}

   // read Key HDR (2 bytes)
   hdr_bytes, err := readNBytesFromFile(file,FC_HDR_FCTYPE_OFFSET+1)
   checkError(err)

   var key_out []byte
   // check Key HDR Type -> If error, abort
   key_hdr, err := getKeyFCFromType(hdr_bytes[FC_HDR_FCTYPE_OFFSET])
   checkError(err)

   key_out,err = key_hdr.retrieveKey(key_in, hdr_bytes, file)
   for stop_decrypt := false; !stop_decrypt; {
      // read ENC HDR (16B) -> if error abort. We need a valid header
      hdr_bytes, err := readNBytesFromFile(file,FC_BSIZE_BYTES_128)
      checkError(err)

      hdr2, err := getEncFCFromType(hdr_bytes[FC_HDR_FCTYPE_OFFSET]) 
      checkError(err)

      hdr2.fromBytes(hdr_bytes)

      // Check if more blocks after this
      if hdr2.isLasttBlock(){
         stop_decrypt = true
      }

      // read Blocks (with nonce). If error during reading blocks abort
      block_bytes  := hdr2.getNBlockBytes()
      block_buffer, err := readNBytesFromFile(file,block_bytes)
      checkError(err)

      p, err := hdr2.decrypt(block_buffer, key_out)
      if err == nil {
         result = append(result, p)
      } 
       
   }
   return result, nil
}

func getEncFCFromType(t byte) (fileCryptEnc, error){
   var enc_hdr fileCryptEnc

   switch t {
      case FC_CLEAR:
           enc_hdr = &ClearFc{}

      case FC_GCM:
           enc_hdr = &GcmFc{}

      default :
           return nil, errors.New("Incorrect Filecrypt handler type")
    }

    return enc_hdr, nil
}

func getKeyFCFromType(t byte) (fileCryptKey, error){
   // check Key HDR Type
   var key_hdr fileCryptKey
   switch t {
       case FC_KEY_T_NOKEY:
             key_hdr = &NoKeyFc{}

       case FC_KEY_T_DIRECT:
             key_hdr = &DirectKeyFc{}

       case FC_KEY_T_PBKDF2:
             key_hdr = &Pbkdf2Fc{}

       default:
             return nil, errors.New("Invalid Key Header")
   }
   return key_hdr, nil
}

