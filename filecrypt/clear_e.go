// No encryption functionality

package filecrypt

import ()

type ClearFc struct {
	fchdr
}

func (hdr *ClearFc) encrypt(fname string, key []byte, cleartext interface{}) error {
	// Encode cleartext to byte stream
	bytestream, err := interfaceEncode(cleartext)
	checkError(err)

	// Start writing to file
	hdr.setNBlocks(len(bytestream))

	fhdr, err := hdr.toBytes()
	checkError(err)

	// Append to file
	file, err := openFileA(fname)
	checkError(err)
	defer file.Close()

	// write header to file
	_, err = file.Write(fhdr)
	checkError(err)

	// bytestream
	_, err = file.Write(bytestream)
	checkError(err)

	return nil
}

func (c ClearFc) decrypt(plaintext, key []byte) (interface{}, error) {
	// decode bytestream to struct
	decoded_data, err := interfaceDecode(plaintext)

	//return decoded_data, err
	return decoded_data, err
}
