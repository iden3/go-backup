package filecrypt

import (
	"crypto/aes"
	"crypto/cipher"
)

type GcmFc struct {
	fchdr
}

// Encrypt data structure and write it/append it as bytetream to a file using GCM 128/256
//   bits depending on key length
func (hdr *GcmFc) encrypt(fname string, key []byte, cleartext interface{}) error {
	cphr, err := aes.NewCipher(key)
	checkError(err)

	gcm, err := cipher.NewGCM(cphr)
	checkError(err)

	// Encode cleartext to byte stream
	bytestream, err := interfaceEncode(cleartext)
	checkError(err)

	// nonce computation
	nonce, err := genRandomBytes(gcm.NonceSize())
	checkError(err)

	// Encrypt and seal
	ciphertext := gcm.Seal(bytestream[:0], nonce, bytestream, nil)

	// Start writing encryption block (Header + Nonce + cipherblock)

	hdr.setNonceSize(len(nonce))
	// add nblocks (including 1 block for nonce)
	hdr.setNBlocks(len(ciphertext) + len(nonce) + hdr.getNoncePaddingLen())

	fhdr, err := hdr.toBytes()
	checkError(err)

	// Append to file
	file, err := openFileA(fname)
	checkError(err)
	defer file.Close()

	// write header to file
	_, err = file.Write(fhdr)
	checkError(err)
	// write nonce
	_, err = file.Write(nonce)
	checkError(err)

	// write nonce padding
	nonce_padding := make([]byte, hdr.getNoncePaddingLen())
	_, err = file.Write(nonce_padding)
	checkError(err)

	// ciphertext
	_, err = file.Write(ciphertext)
	checkError(err)

	return nil
}

// Decrypt and authenticate file containing byte stream using GCM 128/256 depending on key length.
// Resulting bytestream is decoded and original data structure retrieved
func (hdr GcmFc) decrypt(block, key []byte) (interface{}, error) {
	// init cypher
	cypher, err := aes.NewCipher(key)
	checkError(err)

	gcmDecrypt, err := cipher.NewGCM(cypher)
	checkError(err)

	// read nonce
	nonce := block[:hdr.noncesize]
	// read cipherblock
	encrypted_pld := block[hdr.noncesize+hdr.getNoncePaddingLen():]

	// decrypt and authenticate
	plaintext, err := gcmDecrypt.Open(nil, nonce, encrypted_pld, nil)

	if err == nil {
		// decode bytestream to struct
		decoded_data, err := interfaceDecode(plaintext)
		return decoded_data, err

	} else {
		return nil, err
	}

}
