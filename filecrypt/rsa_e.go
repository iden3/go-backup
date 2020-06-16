package filecrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

type RsaFc struct {
	hdre
}

// Encrypt data structure and write it/append it as bytetream to a file using RSA
//   bits depending on key length
func (hdr *RsaFc) encrypt(fname string, key []byte, cleartext interface{}) error {
	// Recover key
	var publicKey rsa.PublicKey
	err := json.Unmarshal(key, &publicKey)
	if err != nil {
		return err
	}
	// Encode cleartext to byte stream
	bytestream, err := interfaceEncode(cleartext)
	if err != nil {
		return fmt.Errorf("interfaceEncode : %w", err)
	}

	if fcBsize[hdr.blocksize] <= len(bytestream) {
		return errors.New("cleartext longer than key len")
	}

	// Encrypt
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &publicKey, bytestream, nil)

	// add nblocks (including 1 block for nonce)
	hdr.setNBlocks(int64(len(ciphertext)))

	fhdr, err := hdr.toBytes()
	if err != nil {
		return fmt.Errorf("toByte : %w", err)
	}

	// Append to file
	file, err := openFileA(fname)
	if err != nil {
		return fmt.Errorf("Open file: %w", err)
	}
	defer file.Close()

	// write header to file
	_, err = file.Write(fhdr)
	if err != nil {
		return fmt.Errorf("Write file: %w", err)
	}

	// ciphertext
	_, err = file.Write(ciphertext)
	if err != nil {
		return fmt.Errorf("Write file: %w", err)
	}

	return nil
}

// Decrypt and authenticate file containing byte stream using RSA depending on key length.
// Resulting bytestream is decoded and original data structure retrieved
func (hdr RsaFc) decrypt(ciphertext, key []byte) (interface{}, error) {
	// Recover key
	var privateKey rsa.PrivateKey
	err := json.Unmarshal(key, &privateKey)
	if err != nil {
		return nil, err
	}

	// decrypt and authenticate
	rng := rand.Reader
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &privateKey, ciphertext, nil)

	if err == nil {
		// decode bytestream to struct
		decodedData, err := interfaceDecode(plaintext)
		return decodedData, err

	} else {
		return nil, err
	}

}
