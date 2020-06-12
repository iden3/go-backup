// No encryption functionality

package filecrypt

import (
	"fmt"
)

type ClearFc struct {
	fchdr
}

func (hdr *ClearFc) encrypt(fname string, key []byte, cleartext interface{}) error {
	// Encode cleartext to byte stream
	bytestream, err := interfaceEncode(cleartext)
	if err != nil {
		return fmt.Errorf("interfaceEncode : %w", err)
	}

	// Start writing to file
	hdr.setNBlocks(len(bytestream))

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

	// bytestream
	_, err = file.Write(bytestream)
	if err != nil {
		return fmt.Errorf("File write : %w", err)
	}

	return nil
}

func (c ClearFc) decrypt(plaintext, key []byte) (interface{}, error) {
	// decode bytestream to struct
	decodedData, err := interfaceDecode(plaintext)

	//return decodedData, err
	return decodedData, err
}
