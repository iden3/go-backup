package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

type GcmFc struct {
	hdre
}

// Encrypt data structure and write it/append it as bytetream to a file using GCM 128/256
//   bits depending on key length
func (hdr *GcmFc) encrypt(fname string, key []byte, cleartext interface{}) error {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("NewCipher : %w", err)
	}

	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		return fmt.Errorf("NewGCM : %w", err)
	}

	// Encode cleartext to byte stream
	bytestream, err := interfaceEncode(cleartext)
	if err != nil {
		return fmt.Errorf("interfaceEncode : %w", err)
	}

	// nonce computation
	nonce, err := genRandomBytes(gcm.NonceSize())
	if err != nil {
		return fmt.Errorf("genRandomBytes : %w", err)
	}

	// Encrypt and seal
	ciphertext := gcm.Seal(bytestream[:0], nonce, bytestream, nil)

	// Start writing encryption block (Header + Nonce + cipherblock)

	hdr.setNonceSize(len(nonce))
	// add nblocks (including 1 block for nonce)
	hdr.setNBlocks(len(ciphertext) + len(nonce) + hdr.getNoncePaddingLen())

	fhdr, err := hdr.toBytes()
	if err != nil {
		return fmt.Errorf("hdr.toBytes : %w", err)
	}

	// Append to file
	file, err := openFileA(fname)
	if err != nil {
		return fmt.Errorf("Open file : %w", err)
	}
	defer file.Close()

	// write header to file
	_, err = file.Write(fhdr)
	if err != nil {
		return fmt.Errorf("Write file : %w", err)
	}
	// write nonce
	_, err = file.Write(nonce)
	if err != nil {
		return fmt.Errorf("Write file : %w", err)
	}

	// write nonce padding
	noncePadding := make([]byte, hdr.getNoncePaddingLen())
	_, err = file.Write(noncePadding)
	if err != nil {
		return fmt.Errorf("Write file : %w", err)
	}

	// ciphertext
	_, err = file.Write(ciphertext)
	if err != nil {
		return fmt.Errorf("Write file : %w", err)
	}

	return nil
}

// Decrypt and authenticate file containing byte stream using GCM 128/256 depending on key length.
// Resulting bytestream is decoded and original data structure retrieved
func (hdr GcmFc) decrypt(block, key []byte) (interface{}, error) {
	// init cypher
	cypher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("NewCipher : %w", err)
	}

	gcmDecrypt, err := cipher.NewGCM(cypher)
	if err != nil {
		return nil, fmt.Errorf("NewGCM : %w", err)
	}

	// read nonce
	nonce := block[:hdr.noncesize]
	// read cipherblock
	encrypted_pld := block[hdr.noncesize+hdr.getNoncePaddingLen():]

	// decrypt and authenticate
	plaintext, err := gcmDecrypt.Open(nil, nonce, encrypted_pld, nil)
	if err != nil {
		return nil, fmt.Errorf("Open : %w", err)
	}

	if err == nil {
		// decode bytestream to struct
		decoded_data, err := interfaceDecode(plaintext)
		return decoded_data, err

	} else {
		return nil, fmt.Errorf("interfaceDecode : %w", err)
	}

}
