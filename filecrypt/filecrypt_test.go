package filecrypt

import (
	"bytes"
	cr "crypto/rand"
	"crypto/rsa"
	"encoding/gob"
	"encoding/json"
	"math/rand"
	"os"
	"testing"
)

const (
	TEST_N_ELEMS  = 1 << 6
	TEST_SALT_LEN = 12
	TEST_NITER    = 60000
)

type FCTest1 struct {
	X [TEST_N_ELEMS]uint64
	T string
}

func initFCTest1(s int) *FCTest1 {
	var testData FCTest1
	for i := 0; i < TEST_N_ELEMS; i++ {
		testData.X[i] = uint64(i + s)
	}
	testData.T = "test1"

	return &testData
}

func initFCMap(n int) map[string][]byte {
	t := make(map[string][]byte)
	for i := 0; i < n; i++ {
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
	testData1 := initFCTest1(12)
	testData2 := initFCTest1(2335)
	testData3 := initFCTest1(123232)
	testData := []*FCTest1{testData1, testData2, testData3}

	// register struct
	gob.Register(&FCTest1{})

	// init key
	key, err := genRandomBytes(FC_BSIZE_BYTES_256)

	tags := [3]string{"BLOCK1", "BLOCK2", "BLOCK3"}
	fc, err := New(3, "./testdata/sample1.dat", nil, key, FC_KEY_T_DIRECT)
	if err != nil {
		t.Error(err)
	}
	// encrypt first block
	err = fc.AddBlock([]byte(tags[0]), FC_GCM, testData1)
	if err != nil {
		t.Error(err)
	}

	// encrypt second block
	err = fc.AddBlock([]byte(tags[1]), FC_GCM, testData2)
	if err != nil {
		t.Error(err)
	}

	// encrypt last block
	err = fc.AddBlock([]byte(tags[2]), FC_GCM, testData3)
	if err != nil {
		t.Error(err)
	}

	// Decode filecrypt
	newFC, err := NewFromFile("./testdata/sample1.dat")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(fc.Nonce(), newFC.Nonce()) {
		t.Error("Nonces not equal")
	}
	newTags := newFC.ListTags()
	// Check Tags
	for idx := 0; idx < len(tags); idx += 1 {
		if !bytes.Equal(newTags[idx], []byte(tags[idx])) {
			t.Error(err)
		}
	}
	result, err := newFC.DecryptAll(key)
	if err != nil {
		t.Error(err)
	}
	if len(result) != 3 {
		t.Error("Unexpected result length")
	}
	r1 := *result[0].(*FCTest1)
	r2 := *result[1].(*FCTest1)
	r3 := *result[2].(*FCTest1)

	if r1 != *testData1 {
		t.Error("Encrypted and decrypted values not equal")
	}
	if r2 != *testData2 {
		t.Error("Encrypted and decrypted values not equal")
	}
	if r3 != *testData3 {
		t.Error("Encrypted and decrypted values not equal")
	}

	for idx := 0; idx < len(tags); idx += 1 {
		result, err := newFC.DecryptSingle([]byte(tags[idx]), key)
		if err != nil {
			t.Error(err)
		}
		r := *result.(*FCTest1)
		if r != *testData[idx] {
			t.Error("Encrypted and decrypted values not equal")
		}

	}
}

func TestFCDirectRSA(t *testing.T) {
	// init tests data
	testData1 := initFCTest1(40)
	testData2 := initFCTest1(80)
	testData3 := initFCTest1(90)
	testData := []*FCTest1{testData1, testData2, testData3}

	// register struct
	gob.Register(&FCTest1{})

	// init key
	privKey, _ := rsa.GenerateKey(cr.Reader, FC_BSIZE_BYTES_2048*8)
	publicKeyB, _ := json.Marshal(privKey.PublicKey)
	privateKeyB, _ := json.Marshal(privKey)

	tags := [3]string{"BLOCK1", "BLOCK2", "BLOCK3"}
	fc, err := New(3, "./testdata/sample1.dat", nil, publicKeyB, FC_KEY_T_DIRECT)
	if err != nil {
		t.Error(err)
	}

	// encrypt first block
	err = fc.AddBlock([]byte(tags[0]), FC_RSA, testData1)
	if err != nil {
		t.Error(err)
	}

	// encrypt second block
	err = fc.AddBlock([]byte(tags[1]), FC_RSA, testData2)
	if err != nil {
		t.Error(err)
	}

	// encrypt last block
	err = fc.AddBlock([]byte(tags[2]), FC_RSA, testData3)
	if err != nil {
		t.Error(err)
	}

	// Decode filecrypt
	newFC, err := NewFromFile("./testdata/sample1.dat")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(fc.Nonce(), newFC.Nonce()) {
		t.Error("Nonces not equal")
	}
	newTags := newFC.ListTags()
	// Check Tags
	for idx := 0; idx < len(tags); idx += 1 {
		if !bytes.Equal(newTags[idx], []byte(tags[idx])) {
			t.Error("Tags are not equal")
		}
	}
	result, err := newFC.DecryptAll(privateKeyB)
	if err != nil {
		t.Error(err)
	}
	if len(result) != 3 {
		t.Error("Unexpected result length")
	}
	r1 := *result[0].(*FCTest1)
	r2 := *result[1].(*FCTest1)
	r3 := *result[2].(*FCTest1)

	if r1 != *testData1 {
		t.Error("Encrypted and decrypted values not equal")
	}
	if r2 != *testData2 {
		t.Error("Encrypted and decrypted values not equal")
	}
	if r3 != *testData3 {
		t.Error("Encrypted and decrypted values not equal")
	}

	for idx := 0; idx < len(tags); idx += 1 {
		result, err := newFC.DecryptSingle([]byte(tags[idx]), privateKeyB)
		if err != nil {
			t.Error(err)
		}
		r := *result.(*FCTest1)
		if r != *testData[idx] {
			t.Error("Encrypted and decrypted values not equal")
		}

	}
}

func TestFCNokeyClear(t *testing.T) {
	// init tests data
	testData1 := initFCTest1(12)
	testData2 := initFCTest1(2335)
	testData3 := initFCTest1(123232)
	testData := []*FCTest1{testData1, testData2, testData3}

	// register struct
	gob.Register(&FCTest1{})

	// init key
	key, err := genRandomBytes(FC_BSIZE_BYTES_256)

	tags := [3]string{"BLOCK1", "BLOCK2", "BLOCK3"}
	fc, err := New(3, "./testdata/sample1.dat", nil, nil, FC_KEY_T_NOKEY)
	if err != nil {
		t.Error(err)
	}

	// encrypt first block
	err = fc.AddBlock([]byte(tags[0]), FC_CLEAR, testData1)
	if err != nil {
		t.Error(err)
	}

	// encrypt second block
	err = fc.AddBlock([]byte(tags[1]), FC_CLEAR, testData2)
	if err != nil {
		t.Error(err)
	}

	// encrypt last block
	err = fc.AddBlock([]byte(tags[2]), FC_CLEAR, testData3)
	if err != nil {
		t.Error(err)
	}

	// Decode filecrypt
	newFC, err := NewFromFile("./testdata/sample1.dat")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(fc.Nonce(), newFC.Nonce()) {
		t.Error("Nonces not equal")
	}
	newTags := newFC.ListTags()
	// Check Tags
	for idx := 0; idx < len(tags); idx += 1 {
		if !bytes.Equal(newTags[idx], []byte(tags[idx])) {
			t.Error(err)
		}
	}
	result, err := newFC.DecryptAll(key)
	if err != nil {
		t.Error(err)
	}
	if len(result) != 3 {
		t.Error("Unexpected result length")
	}
	r1 := *result[0].(*FCTest1)
	r2 := *result[1].(*FCTest1)
	r3 := *result[2].(*FCTest1)

	if r1 != *testData1 {
		t.Error("Encrypted and decrypted values not equal")
	}
	if r2 != *testData2 {
		t.Error("Encrypted and decrypted values not equal")
	}
	if r3 != *testData3 {
		t.Error("Encrypted and decrypted values not equal")
	}

	for idx := 0; idx < len(tags); idx += 1 {
		result, err := newFC.DecryptSingle([]byte(tags[idx]), key)
		if err != nil {
			t.Error(err)
		}
		r := *result.(*FCTest1)
		if r != *testData[idx] {
			t.Error("Encrypted and decrypted values not equal")
		}

	}
}

func TestFCPbkdf2GCM(t *testing.T) {
	// init tests data
	testData1 := initFCTest1(12)
	testData2 := initFCTest1(2335)
	testData3 := initFCTest1(123232)
	testData := []*FCTest1{testData1, testData2, testData3}

	// register struct
	gob.Register(&FCTest1{})

	// init key
	key, err := genRandomBytes(FC_BSIZE_BYTES_256)

	tags := [3]string{"BLOCK1", "BLOCK2", "BLOCK3"}
	fc, err := New(3, "./testdata/sample1.dat", nil, key, FC_KEY_T_PBKDF2)
	if err != nil {
		t.Error(err)
	}

	// encrypt first block
	err = fc.AddBlock([]byte(tags[0]), FC_GCM, testData1)
	if err != nil {
		t.Error(err)
	}

	// encrypt second block
	err = fc.AddBlock([]byte(tags[1]), FC_GCM, testData2)
	if err != nil {
		t.Error(err)
	}

	// encrypt last block
	err = fc.AddBlock([]byte(tags[2]), FC_GCM, testData3)
	if err != nil {
		t.Error(err)
	}

	// Decode filecrypt
	newFC, err := NewFromFile("./testdata/sample1.dat")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(fc.Nonce(), newFC.Nonce()) {
		t.Error("Nonces not equal")
	}
	newTags := newFC.ListTags()
	// Check Tags
	for idx := 0; idx < len(tags); idx += 1 {
		if !bytes.Equal(newTags[idx], []byte(tags[idx])) {
			t.Error(err)
		}
	}
	result, err := newFC.DecryptAll(key)
	if err != nil {
		t.Error(err)
	}
	if len(result) != 3 {
		t.Error("Unexpected result length")
	}
	r1 := *result[0].(*FCTest1)
	r2 := *result[1].(*FCTest1)
	r3 := *result[2].(*FCTest1)

	if r1 != *testData1 {
		t.Error("Encrypted and decrypted values not equal")
	}
	if r2 != *testData2 {
		t.Error("Encrypted and decrypted values not equal")
	}
	if r3 != *testData3 {
		t.Error("Encrypted and decrypted values not equal")
	}

	for idx := 0; idx < len(tags); idx += 1 {
		result, err := newFC.DecryptSingle([]byte(tags[idx]), key)
		if err != nil {
			t.Error(err)
		}
		r := *result.(*FCTest1)
		if r != *testData[idx] {
			t.Error("Encrypted and decrypted values not equal")
		}

	}
}

func TestFCPbkdf2Clear(t *testing.T) {
	// init tests data
	testData1 := initFCTest1(12)
	testData2 := initFCTest1(2335)
	testData3 := initFCTest1(123232)
	testData := []*FCTest1{testData1, testData2, testData3}

	// register struct
	gob.Register(&FCTest1{})

	// init key
	key, err := genRandomBytes(FC_BSIZE_BYTES_256)

	tags := [3]string{"BLOCK1", "BLOCK2", "BLOCK3"}
	fc, err := New(3, "./testdata/sample1.dat", nil, key, FC_KEY_T_PBKDF2)
	if err != nil {
		t.Error(err)
	}

	// encrypt first block
	err = fc.AddBlock([]byte(tags[0]), FC_CLEAR, testData1)
	if err != nil {
		t.Error(err)
	}

	// encrypt second block
	err = fc.AddBlock([]byte(tags[1]), FC_CLEAR, testData2)
	if err != nil {
		t.Error(err)
	}

	// encrypt last block
	err = fc.AddBlock([]byte(tags[2]), FC_CLEAR, testData3)
	if err != nil {
		t.Error(err)
	}

	// Decode filecrypt
	newFC, err := NewFromFile("./testdata/sample1.dat")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(fc.Nonce(), newFC.Nonce()) {
		t.Error("Nonces not equal")
	}
	newTags := newFC.ListTags()
	// Check Tags
	for idx := 0; idx < len(tags); idx += 1 {
		if !bytes.Equal(newTags[idx], []byte(tags[idx])) {
			t.Error(err)
		}
	}
	result, err := newFC.DecryptAll(key)
	if err != nil {
		t.Error(err)
	}
	if len(result) != 3 {
		t.Error("Unexpected result length")
	}
	r1 := *result[0].(*FCTest1)
	r2 := *result[1].(*FCTest1)
	r3 := *result[2].(*FCTest1)

	if r1 != *testData1 {
		t.Error("Encrypted and decrypted values not equal")
	}
	if r2 != *testData2 {
		t.Error("Encrypted and decrypted values not equal")
	}
	if r3 != *testData3 {
		t.Error("Encrypted and decrypted values not equal")
	}

	for idx := 0; idx < len(tags); idx += 1 {
		result, err := newFC.DecryptSingle([]byte(tags[idx]), key)
		if err != nil {
			t.Error(err)
		}
		r := *result.(*FCTest1)
		if r != *testData[idx] {
			t.Error("Encrypted and decrypted values not equal")
		}

	}
}

func TestFCPbkdf2ClearGCM(t *testing.T) {
	// init tests data
	testData1 := initFCTest1(12)
	testData2 := initFCTest1(2335)
	testData3 := initFCTest1(123232)
	testData := []*FCTest1{testData1, testData2, testData3}

	// register struct
	gob.Register(&FCTest1{})

	// init key
	key, err := genRandomBytes(FC_BSIZE_BYTES_256)

	tags := [3]string{"BLOCK1", "BLOCK2", "BLOCK3"}
	fc, err := New(3, "./testdata/sample1.dat", nil, key, FC_KEY_T_PBKDF2)
	if err != nil {
		t.Error(err)
	}

	// encrypt first block
	err = fc.AddBlock([]byte(tags[0]), FC_CLEAR, testData1)
	if err != nil {
		t.Error(err)
	}

	// encrypt second block
	err = fc.AddBlock([]byte(tags[1]), FC_GCM, testData2)
	if err != nil {
		t.Error(err)
	}

	// encrypt last block
	err = fc.AddBlock([]byte(tags[2]), FC_CLEAR, testData3)
	if err != nil {
		t.Error(err)
	}

	// Decode filecrypt
	newFC, err := NewFromFile("./testdata/sample1.dat")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(fc.Nonce(), newFC.Nonce()) {
		t.Error("Nonces not equal")
	}
	newTags := newFC.ListTags()
	// Check Tags
	for idx := 0; idx < len(tags); idx += 1 {
		if !bytes.Equal(newTags[idx], []byte(tags[idx])) {
			t.Error(err)
		}
	}
	result, err := newFC.DecryptAll(key)
	if err != nil {
		t.Error(err)
	}
	if len(result) != 3 {
		t.Error("Unexpected result length")
	}
	r1 := *result[0].(*FCTest1)
	r2 := *result[1].(*FCTest1)
	r3 := *result[2].(*FCTest1)

	if r1 != *testData1 {
		t.Error("Encrypted and decrypted values not equal")
	}
	if r2 != *testData2 {
		t.Error("Encrypted and decrypted values not equal")
	}
	if r3 != *testData3 {
		t.Error("Encrypted and decrypted values not equal")
	}

	for idx := 0; idx < len(tags); idx += 1 {
		result, err := newFC.DecryptSingle([]byte(tags[idx]), key)
		if err != nil {
			t.Error(err)
		}
		r := *result.(*FCTest1)
		if r != *testData[idx] {
			t.Error("Encrypted and decrypted values not equal")
		}

	}
}
