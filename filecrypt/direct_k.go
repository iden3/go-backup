// Use provided key directly for encryption and decryption without any Key Derivation Fuction

package filecrypt

import (
      "errors"
      "os"
)

// Implements Direct Key functionality 
//  Header size : 2 Bytes
//  Format
//    version    [1 Byte]
//    keytype    [1 Byte]
//    key_in
//    key_out

type DirectKeyFc struct{
   version       int
   keytype       int
   key_in        []byte
   key_out       []byte
}

// Hdr format
const (
        FC_DIRECTKEYHDR_END_OFFSET       = 2
)

// Init Hdr Struct
func (hdr *DirectKeyFc) FillHdr(Version, Keytype int, Key_in []byte) error{
  // check errors
  if Version >= FC_HDR_NVERSION || 
     Keytype >= FC_KEY_NTYPE {
       return errors.New("Invalid arguments")
  }

  hdr.version   =  Version
  hdr.keytype   =  Keytype
  hdr.key_in    =  Key_in
  hdr.key_out   =  nil

  return nil
}

// from bytes to Hdr struct
func (hdr *DirectKeyFc) fromBytes(hdr_bytes []byte) {
  hdr.version = int(hdr_bytes[FC_HDR_VERSION_OFFSET])
  hdr.keytype = int(hdr_bytes[FC_HDR_FCTYPE_OFFSET])
  hdr.key_in = nil
  hdr.key_out = nil
}

// From HDR struct to bytes
func (hdr DirectKeyFc) toBytes() ([]byte,error) {
   header     := make([]byte, FC_DIRECTKEYHDR_END_OFFSET)
   header[FC_HDR_VERSION_OFFSET] = byte(hdr.version)
   header[FC_HDR_FCTYPE_OFFSET] = byte(hdr.keytype)

   return header, nil
}


func (hdr *DirectKeyFc) retrieveKey(key_in, d[] byte, f *os.File) ([]byte, error) {
    return key_in, nil
}

// Key generation. In Tx, it writes info to a valid fname. In Rx, it reads key_out
func (hdr *DirectKeyFc) generateKey(fname string) ([]byte, error) {
     // in Tx mode, out key is not available
     if hdr.key_out == nil {
       // Generate key hdr
       fhdr, err := hdr.toBytes()
       checkError(err)

       // Create file 
       file, err := openFileW(fname)
       checkError(err)
       defer file.Close()

       // write header to file
       _, err = file.Write(fhdr)
       checkError(err)
       
       hdr.key_out = hdr.key_in
    }

    return hdr.key_out, nil
}
