/*
   Aux functions
*/

package backuplib

import (
	crand "crypto/rand"
	"github.com/iden3/go-backup/ff"
	"io"
	"reflect"
)

// tmp dirs to be deleted
var rmDirs []string

// expected == obtained
func checkEqual(expected, obtained interface{}) bool {
	flag := false

	switch obtained.(type) {
	case []map[uint64]ff.Element:
		o := obtained.([]map[uint64]ff.Element)
		flag = reflect.DeepEqual(expected, o[0])

	default:
		flag = reflect.DeepEqual(expected, obtained)
	}
	return flag
}

// random nonce of given size
func genRandomBytes(noncesize int) ([]byte, error) {
	nonce := make([]byte, noncesize)
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func KeyOperational() []byte {
	key, _ := ff.NewElement(PRIME)
	key.SetRandom().ToMont()

	return key.ToByte()
}

func clone(b0 []byte) []byte {
	b1 := make([]byte, len(b0))
	copy(b1, b0)
	return b1
}
