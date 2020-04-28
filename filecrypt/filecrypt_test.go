package filecrypt


import (
         "testing"
         "encoding/gob"
         "math/rand"
         "reflect"
         "os"
)


const (
         TEST_N_ELEMS       = 1<<6
         TEST_SALT_LEN      = 12
         TEST_NITER         =  60000
)

type FCTest1 struct {
    X     [TEST_N_ELEMS]uint64
    T     string
}

type FCTest2 struct {
    X   map[string][]byte
}

func initFCTest1(s int) *FCTest1{
  var test_data FCTest1
  for i:=0; i < TEST_N_ELEMS; i++{
     test_data.X[i] = uint64(i+s);
  }
  test_data.T = "test1"

  return &test_data
}


func initFCTest2(s int)*FCTest2{
    var data FCTest2
    data.X = initFCMap(s)
    return &data
}

func initFCMap(n int) map[string][]byte{
   t := make(map[string][]byte)
   for i:=0 ; i< n ; i++{
      st := RandStringBytes(5)
      t[st], _ = genRandomBytes((i % 14) + 1)
   }

   return t
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
    b := make([]byte, n)
    for i := range b {
        b[i] = letterBytes[rand.Intn(len(letterBytes))]
    }
    return string(b)
}


func init() {
   if _, err := os.Stat("./testdata"); os.IsNotExist(err) {
      os.Mkdir("./testdata", 0755)
   }
}
func TestFCDirectGCM(t *testing.T) {
   // init tests data
   test_data1 := initFCTest1(12)
   test_data2 := initFCTest1(2335)
   test_data3 := initFCTest2(4)
   

  // register struct
  gob.Register(&FCTest1{})
  gob.Register(&FCTest2{})

  // init key
  key,err := genRandomBytes(FC_BSIZE_BYTES_256)

  // init key hdr
  hdr_k := &DirectKeyFc{}
  err = hdr_k.FillHdr(TEST_VERSION, FC_KEY_T_DIRECT, key)
  if err != nil {
      t.Error(err)
  }

  // encrypt first block
  hdr_e := &GcmFc{}
  err = hdr_e.FillHdr(TEST_VERSION, FC_GCM, FC_BSIZE_BYTES_256 , FC_HDR_BIDX_FIRST )
  if err != nil {
      t.Error(err)
  }
  err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data1 )
  if err != nil{
     t.Error(err)
  }


  // encrypt second block
  err = hdr_e.FillHdr(TEST_VERSION, FC_GCM, FC_BSIZE_BYTES_256 , FC_HDR_BIDX_MID)
  if err != nil {
      t.Error(err)
  }
  err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data2 )
  if err != nil{
     t.Error(err)
  }

  // encrypt last block
  err = hdr_e.FillHdr(TEST_VERSION, FC_GCM, FC_BSIZE_BYTES_256 , FC_HDR_BIDX_LAST)
  if err != nil {
      t.Error(err)
  }
  err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data3 )
  if err != nil{
     t.Error(err)
  }
  result, err := Decrypt("./testdata/sample1.dat", key)
  if err != nil{
     t.Error(err)
  }
  if len(result) != 3{
     t.Error("Unexpected result length")
  }
  r1 := *result[0].(*FCTest1)
  r2 := *result[1].(*FCTest1)
  r3 := *result[2].(*FCTest2)

  if r1 != *test_data1 {
     t.Error("Encrypted and decrypted values not equal")
  }
  if r2 != *test_data2 {
     t.Error("Encrypted and decrypted values not equal")
  }
  if !reflect.DeepEqual(r3.X, (*test_data3).X){
     t.Error("Encrypted and decrypted values not equal")
  }
}



func TestFCNokeyClear(t *testing.T) {
   // init tests data
   test_data1 := initFCTest1(12)
   test_data2 := initFCTest1(2335)
   test_data3 := initFCTest2(4)
   

  // register struct
  gob.Register(&FCTest1{})
  gob.Register(&FCTest2{})

  // init key hdr
  hdr_k := &NoKeyFc{}
  err := hdr_k.FillHdr(TEST_VERSION, FC_KEY_T_NOKEY)
  if err != nil {
      t.Error(err)
  }

  // encrypt first block
  hdr_e := &ClearFc{}
  err = hdr_e.FillHdr(TEST_VERSION, FC_CLEAR, FC_BSIZE_BYTES_256 , FC_HDR_BIDX_FIRST )
  if err != nil {
      t.Error(err)
  }
  err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data1 )
  if err != nil{
     t.Error(err)
  }


  // encrypt second block
  err = hdr_e.FillHdr(TEST_VERSION, FC_CLEAR, FC_BSIZE_BYTES_256 , FC_HDR_BIDX_MID)
  if err != nil {
      t.Error(err)
  }
  err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data2 )
  if err != nil{
     t.Error(err)
  }

  // encrypt last block
  err = hdr_e.FillHdr(TEST_VERSION, FC_CLEAR, FC_BSIZE_BYTES_256 , FC_HDR_BIDX_LAST)
  if err != nil {
      t.Error(err)
  }
  err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data3 )
  if err != nil{
     t.Error(err)
  }
  result, err := Decrypt("./testdata/sample1.dat", nil)
  if err != nil{
     t.Error(err)
  }
  if len(result) != 3{
     t.Error("Unexpected result length")
  }
  r1 := *result[0].(*FCTest1)
  r2 := *result[1].(*FCTest1)
  r3 := *result[2].(*FCTest2)

  if r1 != *test_data1 {
     t.Error("Encrypted and decrypted values not equal")
  }
  if r2 != *test_data2 {
     t.Error("Encrypted and decrypted values not equal")
  }
  if !reflect.DeepEqual(r3.X, (*test_data3).X){
     t.Error("Encrypted and decrypted values not equal")
  }
}


func TestFCPbkdf2GCM(t *testing.T) {
   // init tests data
   test_data1 := initFCTest1(12)
   test_data2 := initFCTest1(2335)
   test_data3 := initFCTest2(4)
   

  // register struct
  gob.Register(&FCTest1{})
  gob.Register(&FCTest2{})

  // init key
  key,err := genRandomBytes(FC_BSIZE_BYTES_128)

  // init key hdr
  hdr_k := &Pbkdf2Fc{}
  err = hdr_k.FillHdr(
                      TEST_VERSION,
                      FC_KEY_T_PBKDF2,
                      FC_HASH_SHA256,
                      TEST_NITER,
                      FC_BSIZE_BYTES_256, 
                      TEST_SALT_LEN,
                      key)
  if err != nil {
      t.Error(err)
  }

  // encrypt first block
  hdr_e := &GcmFc{}
  err = hdr_e.FillHdr(TEST_VERSION, FC_GCM, FC_BSIZE_BYTES_256 , FC_HDR_BIDX_FIRST )
  if err != nil {
      t.Error(err)
  }
  err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data1 )
  if err != nil{
     t.Error(err)
  }


  // encrypt second block
  err = hdr_e.FillHdr(TEST_VERSION, FC_GCM, FC_BSIZE_BYTES_256 , FC_HDR_BIDX_MID)
  if err != nil {
      t.Error(err)
  }
  err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data2 )
  if err != nil{
     t.Error(err)
  }

  // encrypt last block
  err = hdr_e.FillHdr(TEST_VERSION, FC_GCM, FC_BSIZE_BYTES_256 , FC_HDR_BIDX_LAST)
  if err != nil {
      t.Error(err)
  }
  err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data3 )
  if err != nil{
     t.Error(err)
  }
  result, err := Decrypt("./testdata/sample1.dat", key)
  if err != nil{
     t.Error(err)
  }
  if len(result) != 3{
     t.Error("Unexpected result length")
  }
  r1 := *result[0].(*FCTest1)
  r2 := *result[1].(*FCTest1)
  r3 := *result[2].(*FCTest2)

  if r1 != *test_data1 {
     t.Error("Encrypted and decrypted values not equal")
  }
  if r2 != *test_data2 {
     t.Error("Encrypted and decrypted values not equal")
  }
  if !reflect.DeepEqual(r3.X, (*test_data3).X){
     t.Error("Encrypted and decrypted values not equal")
  }
}

func TestFCPbkdf2Clear(t *testing.T) {
   // init tests data
   test_data1 := initFCTest1(12)
   test_data2 := initFCTest1(2335)
   test_data3 := initFCTest2(4)
   

  // register struct
  gob.Register(&FCTest1{})
  gob.Register(&FCTest2{})

  // init key
  key,err := genRandomBytes(FC_BSIZE_BYTES_128)

  // init key hdr
  hdr_k := &Pbkdf2Fc{}
  err = hdr_k.FillHdr(
                      TEST_VERSION,
                      FC_KEY_T_PBKDF2,
                      FC_HASH_SHA256,
                      TEST_NITER,
                      FC_BSIZE_BYTES_256, 
                      TEST_SALT_LEN,
                      key)
  if err != nil {
      t.Error(err)
  }

  // encrypt first block
  hdr_e := &ClearFc{}
  err = hdr_e.FillHdr(TEST_VERSION, FC_CLEAR, FC_BSIZE_BYTES_256 , FC_HDR_BIDX_FIRST )
  if err != nil {
      t.Error(err)
  }
  err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data1 )
  if err != nil{
     t.Error(err)
  }


  // encrypt second block
  err = hdr_e.FillHdr(TEST_VERSION, FC_CLEAR, FC_BSIZE_BYTES_256 , FC_HDR_BIDX_MID)
  if err != nil {
      t.Error(err)
  }
  err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data2 )
  if err != nil{
     t.Error(err)
  }

  // encrypt last block
  err = hdr_e.FillHdr(TEST_VERSION, FC_CLEAR, FC_BSIZE_BYTES_256 , FC_HDR_BIDX_LAST)
  if err != nil {
      t.Error(err)
  }
  err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data3 )
  if err != nil{
     t.Error(err)
  }
  result, err := Decrypt("./testdata/sample1.dat", key)
  if err != nil{
     t.Error(err)
  }
  if len(result) != 3{
     t.Error("Unexpected result length")
  }
  r1 := *result[0].(*FCTest1)
  r2 := *result[1].(*FCTest1)
  r3 := *result[2].(*FCTest2)

  if r1 != *test_data1 {
     t.Error("Encrypted and decrypted values not equal")
  }
  if r2 != *test_data2 {
     t.Error("Encrypted and decrypted values not equal")
  }
  if !reflect.DeepEqual(r3.X, (*test_data3).X){
     t.Error("Encrypted and decrypted values not equal")
  }
}



