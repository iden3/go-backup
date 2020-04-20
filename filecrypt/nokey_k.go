package filecrypt

import (
      "errors"
      "os"
)

// Implements No Key functionality 
//  Header size : 2 Bytes
//  Format
//    version [1 Byte]
//    type    [1 Byte]

type NoKeyFc struct{
   version       int
   keytype       int
   key_in        []byte
   key_out       []byte
}

// Hdr format
const (
        FC_NOKEYHDR_END_OFFSET       = 2
)

// Init Hdr Struct
func (hdr *NoKeyFc) FillHdr(Version, Keytype int) error{
  // check errors
  if Version >= FC_HDR_NVERSION || 
     Keytype >= FC_KEY_NTYPE {
       return errors.New("Invalid arguments")
  }

  hdr.version   = Version
  hdr.keytype   = Keytype
  hdr.key_in    = nil
  hdr.key_out   = nil

  return nil
}

// from bytes to Hdr struct
func (hdr *NoKeyFc) fromBytes(hdr_bytes []byte) {
  hdr.version = int(hdr_bytes[FC_HDR_VERSION_OFFSET])
  hdr.keytype = int(hdr_bytes[FC_HDR_FCTYPE_OFFSET])
  hdr.key_in  = nil
  hdr.key_out  = nil
 }

// From HDR struct to bytes
func (hdr NoKeyFc) toBytes() ([]byte,error) {
   header     := make([]byte, FC_NOKEYHDR_END_OFFSET)
   header[FC_HDR_VERSION_OFFSET] = byte(hdr.version)
   header[FC_HDR_FCTYPE_OFFSET] = byte(hdr.keytype)

   return header, nil
}


func (hdr *NoKeyFc) retrieveKey(key_in, d[] byte,f *os.File) ([]byte, error) {
    return nil, nil
}

func (hdr *NoKeyFc) generateKey(fname string) ([]byte, error) {
    // in Tx mode, out key is not available
    if hdr.key_out == nil {
      // Generate key
      fhdr, err := hdr.toBytes()
      checkError(err)

      // Create file 
      file, err := openFileW(fname)
      checkError(err)
      defer file.Close()

      // write header to file
      _, err = file.Write(fhdr)
      checkError(err)

      hdr.key_out = make([]byte,1)
    }

    return nil, nil
}

