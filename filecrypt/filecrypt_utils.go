// support rutines for filecrypt package

package filecrypt

import (
        "encoding/gob"
        "crypto/rand"
        "bytes"
        "errors"
        "io"
        "os"
)


// interfaceEnconde encodes the interface value into encoder. It is used to encode
//  arbitrary data strcutires into a byte stream
//  See -> https://golang.org/pkg/encoding/gob/#NewEncoder
func interfaceEncode( p interface{}) ([]byte, error){
  // initialize encoder
  var network bytes.Buffer
  enc := gob.NewEncoder(&network)
  err := enc.Encode(&p)
  if err != nil {
        return nil, err
  }
  return network.Bytes(), nil

}


// interfaceDecode decodes the next interface value from the byte stream and returns it as
// the original data structure. Module using FC decrypt needs to register data structures.
//   For example, to register a struct called FCTest, add the following line:
//   gob.Register(FCTest{})
//  See -> https://golang.org/pkg/encoding/gob/#NewEncoder
func interfaceDecode(e []byte) (interface{},error) {
  network := bytes.NewBuffer(e)
  dec := gob.NewDecoder(network)
  var p interface{}
  err := dec.Decode(&p)
  if err != nil {
    return nil, err
  }
  return p, nil
}

// Generate N random bytes.
func genRandomBytes(noncesize int) ([]byte, error) {
    nonce := make([]byte, noncesize)
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    return nonce, nil
}


// Open new file 
func openFileW(fname string)  (*os.File, error) {

    file, err := os.Create(fname)

    return file, err
}

// Open file to append data
func openFileA(fname string)  (*os.File, error) {
    fmode := os.O_WRONLY | os.O_APPEND

    file, err := os.OpenFile(fname, fmode, 0644)

    return file, err
}
// Open file to read data
func openFileR(fname string)  (*os.File, error) {
    fmode := os.O_RDONLY

    file, err := os.OpenFile(fname, fmode, 0644)

    return file, err
}

// Check errors
func checkError(e error) {
   if e != nil {
      panic(e)
   }
}

func readNBytesFromFile(f *os.File, n int) ([]byte,error) {
    buf := make([]byte,n)
    bytes_read , err := f.Read(buf)
    if bytes_read < n || err != nil {
       return nil, errors.New("Incorrect file format")
    }
    return buf, nil
}
