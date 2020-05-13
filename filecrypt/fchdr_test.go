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
	hdr := &ClearFc{}
	err := hdr.FillHdr(TEST_VERSION, TEST0_TYPE, TEST0_BLOCK_SIZE_BYTES, TEST0_BIDX)
	if err != nil {
		t.Error(err)
	}

	// add blocks
	hdr.setNBlocks(TEST_LEN)
	// write hdr to bytes
	hdr_bytes, err := hdr.toBytes()
	if err != nil {
		t.Error(err)
	}

	// retrieve hdr from bytes
	hdr2 := &ClearFc{}
	hdr2.fromBytes(hdr_bytes)

	if *hdr != *hdr2 {
		t.Error("FC handles not equal")
		fmt.Println("HDR1 : ", *hdr)
		fmt.Println("HDR2  : ", *hdr2)
	}

	expected_hdr := ClearFc{
		fchdr: fchdr{
			version:        TEST_VERSION,
			block_idx:      TEST0_BIDX,
			fctype:         TEST0_TYPE,
			blocksize:      TEST0_BLOCK_SIZE,
			noncesize:      0,
			last_blocksize: TEST0_LAST_BSIZE,
			nblocks:        TEST0_NBLOCKS,
		},
	}

	if *hdr != expected_hdr {
		t.Error("FC handles not equal")
		fmt.Println("Expected HDR  : ", expected_hdr)
		fmt.Println("Obtainted HDR : ", *hdr)
	}
}

func TestFCryptNoKeyHdr(t *testing.T) {
	// Generate No Key Header
	hdr := &NoKeyFc{}
	err := hdr.FillHdr(TEST_VERSION, TEST1_TYPE)
	if err != nil {
		t.Error(err)
	}

	// write hdr to bytes
	hdr_bytes, err := hdr.toBytes()
	if err != nil {
		t.Error(err)
	}

	// retrieve hdr from bytes
	hdr2 := &NoKeyFc{}
	hdr2.fromBytes(hdr_bytes)

	if !isNoKeyHdrEqual(hdr, hdr2) {
		t.Error("FC handles not equal")
		fmt.Println("HDR1 : ", *hdr)
		fmt.Println("HDR2  : ", *hdr2)
	}

	expected_hdr := &NoKeyFc{
		version: TEST_VERSION,
		keytype: TEST1_TYPE,
	}

	if !isNoKeyHdrEqual(hdr, expected_hdr) {
		t.Error("FC handles not equal")
		fmt.Println("Expected HDR  : ", expected_hdr)
		fmt.Println("Obtainted HDR : ", *hdr)
	}
}

func TestFCryptGCMHdr(t *testing.T) {
	// Generate GCM Encryption Header
	hdr := &GcmFc{}
	err := hdr.FillHdr(TEST_VERSION, TEST2_TYPE, TEST2_BLOCK_SIZE_BYTES, TEST2_BIDX)

	if err != nil {
		t.Error(err)
	}

	// add nonce
	hdr.setNonceSize(TEST_NONCE_SIZE)

	// add blocks
	hdr.setNBlocks(TEST_LEN)

	// write hdr to bytes
	hdr_bytes, err := hdr.toBytes()
	if err != nil {
		t.Error(err)
	}

	// retrieve hdr from bytes
	hdr2 := &GcmFc{}
	hdr2.fromBytes(hdr_bytes)

	if *hdr != *hdr2 {
		t.Error("FC handles not equal")
		fmt.Println("HDR1 : ", *hdr)
		fmt.Println("HDR2  : ", *hdr2)
	}

	expected_hdr := GcmFc{
		fchdr{
			version:        TEST_VERSION,
			block_idx:      TEST2_BIDX,
			fctype:         TEST2_TYPE,
			blocksize:      TEST2_BLOCK_SIZE,
			noncesize:      TEST2_NONCE_SIZE,
			last_blocksize: TEST2_LAST_BSIZE,
			nblocks:        TEST2_NBLOCKS,
		},
	}

	if *hdr != expected_hdr {
		t.Error("FC handles not equal")
		fmt.Println("Expected HDR  : ", expected_hdr)
		fmt.Println("Obtainted HDR : ", *hdr)
	}

	//check padding was correctly computed
	nonce_padding_len := hdr.getNoncePaddingLen()
	if nonce_padding_len != TEST2_NONCE_PADDING {
		t.Error("Unexpected Nonce Padding Length")
		fmt.Println("Expected Nonce Len : ", TEST2_NONCE_PADDING)
		fmt.Println("Obtained Nonce Len : ", nonce_padding_len)
	}
}

func TestFCryptPNoKeyHdr(t *testing.T) {
	// Generate PBKDF2 Key Header
	key_in, err := genRandomBytes(TEST_KEYIN_LEN)
	hdr := &Pbkdf2Fc{}
	err = hdr.FillHdr(TEST_VERSION, TEST3_TYPE, TEST_HASH_TYPE,
		TEST_ITER, TEST_OUTLEN, TEST_SALTLEN, key_in)
	if err != nil {
		t.Error(err)
	}

	// write hdr to bytes
	hdr_bytes, err := hdr.toBytes()
	if err != nil {
		t.Error(err)
	}

	// retrieve hdr from bytes
	hdr2 := &Pbkdf2Fc{}
	hdr2.fromBytes(hdr_bytes)

	if !isPbkdf2HdrEqual(hdr, hdr2) {
		t.Error("FC handles not equal")
		fmt.Println("HDR1 : ", *hdr)
		fmt.Println("HDR2  : ", *hdr2)
	}

	expected_hdr := &Pbkdf2Fc{
		version:  TEST_VERSION,
		keytype:  TEST3_TYPE,
		hdrlen:   FC_PBKDF2HDR_SALT_OFFSET + TEST_SALTLEN,
		hashtype: TEST_HASH_TYPE,
		iter:     TEST_ITER,
		outlen:   TEST_OUTLEN,
		saltlen:  TEST_SALTLEN,
	}

	if !isPbkdf2HdrEqual(hdr, expected_hdr) {
		t.Error("FC handles not equal")
		fmt.Println("Expected HDR  : ", expected_hdr)
		fmt.Println("Obtainted HDR : ", *hdr)
	}
}

func TestFCryptDirectKeyHdr(t *testing.T) {
	// Generate Direct Key Header
	key_in, err := genRandomBytes(TEST_KEYIN_LEN)
	hdr := &DirectKeyFc{}
	err = hdr.FillHdr(TEST_VERSION, TEST4_TYPE, key_in)
	if err != nil {
		t.Error(err)
	}

	// write hdr to bytes
	hdr_bytes, err := hdr.toBytes()
	if err != nil {
		t.Error(err)
	}

	// retrieve hdr from bytes
	hdr2 := &DirectKeyFc{}
	hdr2.fromBytes(hdr_bytes)

	if !isDirectKeyHdrEqual(hdr, hdr2) {
		t.Error("FC handles not equal")
		fmt.Println("HDR1 : ", *hdr)
		fmt.Println("HDR2  : ", *hdr2)
	}

	expected_hdr := &DirectKeyFc{
		version: TEST_VERSION,
		keytype: TEST4_TYPE,
	}

	if !isDirectKeyHdrEqual(hdr, expected_hdr) {
		t.Error("FC handles not equal")
		fmt.Println("Expected HDR  : ", expected_hdr)
		fmt.Println("Obtainted HDR : ", *hdr)
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
