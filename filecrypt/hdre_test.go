package filecrypt

import (
	"fmt"
	"testing"
	//"encoding/gob"
)

const (
	// General test params
	TEST_VERSION    = FC_HDR_VERSION_1
	TEST_NONCE_SIZE = 12
	TEST_LEN        = (1 << 10) + 15

	// Clear Key test
	TEST0_TYPE             = FC_CLEAR
	TEST0_BLOCK_SIZE       = FC_HDR_BSIZE_128
	TEST0_BLOCK_SIZE_BYTES = 16
	TEST0_BIDX             = FC_HDR_BIDX_SINGLE
	TEST0_LAST_BSIZE       = TEST_LEN % TEST0_BLOCK_SIZE_BYTES
	TEST0_NBLOCKS          = int((TEST_LEN + TEST0_BLOCK_SIZE_BYTES - 1) / TEST0_BLOCK_SIZE_BYTES)

	// No Key test
	TEST1_TYPE = FC_KEY_T_NOKEY

	// GCM Test
	TEST2_NONCE_SIZE       = 12
	TEST2_BLOCK_SIZE       = FC_HDR_BSIZE_256
	TEST2_BLOCK_SIZE_BYTES = 32
	TEST2_NONCE_PADDING    = TEST2_BLOCK_SIZE_BYTES - 12
	TEST2_BIDX             = FC_HDR_BIDX_SINGLE
	TEST2_TYPE             = FC_GCM
	TEST2_LAST_BSIZE       = TEST_LEN % TEST2_BLOCK_SIZE_BYTES
	TEST2_NBLOCKS          = int((TEST_LEN + TEST2_BLOCK_SIZE_BYTES - 1) / TEST2_BLOCK_SIZE_BYTES)

	//PBKDF2 Test
	TEST3_TYPE     = FC_KEY_T_PBKDF2
	TEST_HASH_TYPE = FC_HASH_SHA256
	TEST_ITER      = 60000
	TEST_OUTLEN    = 32
	TEST_SALTLEN   = 12
	TEST_KEYIN_LEN = 16

	// DIRECT Key test
	TEST4_TYPE = FC_KEY_T_DIRECT
)

func TestFCryptClearHdr(t *testing.T) {

	// Generate No Encryption Header
	hdr, err := NewHdrEncrypt(TEST_VERSION, TEST0_TYPE, TEST0_BLOCK_SIZE_BYTES, TEST0_BIDX)
	if err != nil {
		t.Error(err)
	}

	// add blocks
	hdr.setNBlocks(TEST_LEN)
	// write hdr to bytes
	hdrBytes, err := hdr.toBytes()
	if err != nil {
		t.Error(err)
	}

	// retrieve hdr from bytes
	hdr2 := &ClearFc{}
	hdr2.fromBytes(hdrBytes)

	newHdr := &ClearFc{}
	switch hdr.(type) {
	case *ClearFc:
		newHdr = hdr.(*ClearFc)
	default:
		t.Error("FC handles not equal")
	}
	if *newHdr != *hdr2 {
		t.Error("FC handles not equal")
		fmt.Println("HDR1 : ", hdr)
		fmt.Println("HDR2  : ", hdr2)
	}

}

func TestFCryptNoKeyHdr(t *testing.T) {
	// Generate No Key Header
	hdr, err := NewHdrKey(nil, TEST_VERSION, TEST1_TYPE)
	if err != nil {
		t.Error(err)
	}

	// write hdr to bytes
	hdrBytes, err := hdr.toBytes()
	if err != nil {
		t.Error(err)
	}

	// retrieve hdr from bytes
	hdr2 := &NoKeyFc{}
	hdr2.fromBytes(hdrBytes)

	newHdr := &NoKeyFc{}
	switch hdr.(type) {
	case *NoKeyFc:
		newHdr = hdr.(*NoKeyFc)
	default:
		t.Error(err)
	}

	if !isNoKeyHdrEqual(newHdr, hdr2) {
		t.Error("FC handles not equal")
		fmt.Println("HDR1 : ", newHdr)
		fmt.Println("HDR2  : ", *hdr2)
	}

	expectedHdr := &NoKeyFc{
		version: TEST_VERSION,
		keytype: TEST1_TYPE,
	}

	if !isNoKeyHdrEqual(newHdr, expectedHdr) {
		t.Error("FC handles not equal")
		fmt.Println("Expected HDR  : ", expectedHdr)
		fmt.Println("Obtainted HDR : ", newHdr)
	}
}

func TestFCryptGCMHdr(t *testing.T) {
	// Generate GCM Encryption Header
	hdr, err := NewHdrEncrypt(TEST_VERSION, TEST2_TYPE, TEST2_BLOCK_SIZE_BYTES, TEST2_BIDX)

	if err != nil {
		t.Error(err)
	}

	// add nonce
	hdr.setNonceSize(TEST_NONCE_SIZE)

	// add blocks
	hdr.setNBlocks(TEST_LEN)

	// write hdr to bytes
	hdrBytes, err := hdr.toBytes()
	if err != nil {
		t.Error(err)
	}

	// retrieve hdr from bytes
	hdr2 := &GcmFc{}
	hdr2.fromBytes(hdrBytes)

	switch hdr.(type) {
	case *GcmFc:
		newHdr := *hdr.(*GcmFc)
		if newHdr != *hdr2 {
			t.Error("FC handles not equal")
			fmt.Println("HDR1 : ", newHdr)
			fmt.Println("HDR2  : ", *hdr2)
		}
	default:
		t.Error(err)
	}

	expectedHdr := GcmFc{
		hdre{
			version:       TEST_VERSION,
			blockIdx:      TEST2_BIDX,
			fctype:        TEST2_TYPE,
			blocksize:     TEST2_BLOCK_SIZE,
			noncesize:     TEST2_NONCE_SIZE,
			lastBlocksize: TEST2_LAST_BSIZE,
			nblocks:       TEST2_NBLOCKS,
		},
	}

	newHdr := *hdr.(*GcmFc)
	if newHdr != expectedHdr {
		t.Error("FC handles not equal")
		fmt.Println("Expected HDR  : ", expectedHdr)
		fmt.Println("Obtainted HDR : ", newHdr)
	}

	//check padding was correctly computed
	noncePaddingLen := hdr.getNoncePaddingLen()
	if noncePaddingLen != TEST2_NONCE_PADDING {
		t.Error("Unexpected Nonce Padding Length")
		fmt.Println("Expected Nonce Len : ", TEST2_NONCE_PADDING)
		fmt.Println("Obtained Nonce Len : ", noncePaddingLen)
	}
}

func TestFCryptPNoKeyHdr(t *testing.T) {
	// Generate PBKDF2 Key Header
	keyIn, err := genRandomBytes(TEST_KEYIN_LEN)
	hdr, err := NewHdrKey(keyIn, TEST_VERSION, TEST3_TYPE, TEST_HASH_TYPE,
		TEST_ITER, TEST_OUTLEN, TEST_SALTLEN)
	if err != nil {
		t.Error(err)
	}

	// write hdr to bytes
	hdrBytes, err := hdr.toBytes()
	if err != nil {
		t.Error(err)
	}

	// retrieve hdr from bytes
	hdr2 := &Pbkdf2Fc{}
	hdr2.fromBytes(hdrBytes)

	newHdr := &Pbkdf2Fc{}
	switch hdr.(type) {
	case *Pbkdf2Fc:
		newHdr = hdr.(*Pbkdf2Fc)
	default:
		t.Error(err)
	}
	if !isPbkdf2HdrEqual(newHdr, hdr2) {
		t.Error("FC handles not equal")
		fmt.Println("HDR1 : ", *newHdr)
		fmt.Println("HDR2  : ", *hdr2)
	}

	expectedHdr := &Pbkdf2Fc{
		version:  TEST_VERSION,
		keytype:  TEST3_TYPE,
		hdrlen:   FC_PBKDF2HDR_SALT_OFFSET + TEST_SALTLEN,
		hashtype: TEST_HASH_TYPE,
		iter:     TEST_ITER,
		outlen:   TEST_OUTLEN,
		saltlen:  TEST_SALTLEN,
	}

	if !isPbkdf2HdrEqual(newHdr, expectedHdr) {
		t.Error("FC handles not equal")
		fmt.Println("Expected HDR  : ", expectedHdr)
		fmt.Println("Obtainted HDR : ", *newHdr)
	}
}

func TestFCryptDirectKeyHdr(t *testing.T) {
	// Generate Direct Key Header
	keyIn, err := genRandomBytes(TEST_KEYIN_LEN)
	hdr, err := NewHdrKey(keyIn, TEST_VERSION, TEST4_TYPE)
	if err != nil {
		t.Error(err)
	}

	// write hdr to bytes
	hdrBytes, err := hdr.toBytes()
	if err != nil {
		t.Error(err)
	}

	// retrieve hdr from bytes
	hdr2 := &DirectKeyFc{}
	hdr2.fromBytes(hdrBytes)

	newHdr := &DirectKeyFc{}
	switch hdr.(type) {
	case *DirectKeyFc:
		newHdr = hdr.(*DirectKeyFc)
	default:
		t.Error(err)
	}
	if !isDirectKeyHdrEqual(newHdr, hdr2) {
		t.Error("FC handles not equal")
		fmt.Println("HDR1 : ", *newHdr)
		fmt.Println("HDR2  : ", *hdr2)
	}

	expectedHdr := &DirectKeyFc{
		version: TEST_VERSION,
		keytype: TEST4_TYPE,
	}

	if !isDirectKeyHdrEqual(newHdr, expectedHdr) {
		t.Error("FC handles not equal")
		fmt.Println("Expected HDR  : ", expectedHdr)
		fmt.Println("Obtainted HDR : ", *newHdr)
	}
}

func isPbkdf2HdrEqual(hdr1, hdr2 *Pbkdf2Fc) bool {

	if hdr1.version == hdr2.version &&
		hdr1.keytype == hdr2.keytype &&
		hdr1.hdrlen == hdr2.hdrlen &&
		hdr1.iter == hdr2.iter &&
		hdr1.outlen == hdr2.outlen &&
		hdr1.saltlen == hdr2.saltlen {
		return true
	}
	return false
}

func isNoKeyHdrEqual(hdr1, hdr2 *NoKeyFc) bool {

	if hdr1.version == hdr2.version &&
		hdr1.keytype == hdr2.keytype {
		return true
	}
	return false
}

func isDirectKeyHdrEqual(hdr1, hdr2 *DirectKeyFc) bool {

	if hdr1.version == hdr2.version &&
		hdr1.keytype == hdr2.keytype {
		return true
	}
	return false
}
