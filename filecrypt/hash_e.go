// No encryption functionality

package filecrypt

import (
	"crypto/sha256"
	"fmt"
)

type HashFc struct {
	hdre
}

func (hdr *HashFc) encrypt(fname string, key []byte, cleartext interface{}) error {
	// Encode cleartext to byte stream
	bytestream, err := interfaceEncode(cleartext)
	if err != nil {
		return fmt.Errorf("interfaceEncode : %w", err)
	}

	// Start writing to file
	hdr.setNBlocks(FC_BSIZE_BYTES_256)

	fhdr, err := hdr.toBytes()
	if err != nil {
		return fmt.Errorf("toBytes : %w", err)
	}

	// Append to file
	file, err := openFileA(fname)
	if err != nil {
		return fmt.Errorf("toBytes : %w", err)
	}
	defer file.Close()

	// write header to file
	_, err = file.Write(fhdr)
	if err != nil {
		return fmt.Errorf("File write : %w", err)
	}

	var hashB []byte
	switch hdr.blocksize {
	case FC_HDR_BSIZE_256:
		// compute hash HASH_SHA256
		bytestreamHash := sha256.Sum256(bytestream)
		hashB = bytestreamHash[:]

	default:
		return fmt.Errorf("Inncorrect block size")
	}

	_, err = file.Write(hashB)
	if err != nil {
		return fmt.Errorf("File write : %w", err)
	}

	return nil
}

func (hdr HashFc) decrypt(plaintext, key []byte) (interface{}, error) {
	return plaintext, nil
}
