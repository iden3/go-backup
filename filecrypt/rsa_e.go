package filecrypt

import (
	"crypto/rsa"
        "crypto/rand"
        "crypto/sha256"
	"encoding/json"
        "errors"
)

type RsaFc struct {
	fchdr
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
	checkError(err)

        if fc_bsize[hdr.blocksize] <= len(bytestream){
             return errors.New("cleartext longer than key len")
        }

	// Encrypt 
        rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &publicKey, bytestream, nil)

	// add nblocks (including 1 block for nonce)
	hdr.setNBlocks(len(ciphertext))

	fhdr, err := hdr.toBytes()
	checkError(err)

	// Append to file
	file, err := openFileA(fname)
	checkError(err)
	defer file.Close()

	// write header to file
	_, err = file.Write(fhdr)
	checkError(err)

	// ciphertext
	_, err = file.Write(ciphertext)
	checkError(err)

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
		decoded_data, err := interfaceDecode(plaintext)
		return decoded_data, err

	} else {
		return nil, err
	}

}
