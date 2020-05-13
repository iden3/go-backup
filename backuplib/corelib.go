/* 
   Auxiliary information emulating claims, ZKP and Merkle Tree (these types are defined
   somewhere in core library)
   Strcuture and contents are not important. Just deinfing some arbitrary data structures
   to do backup
*/

package backuplib

import (
	"math/rand"
  	"github.com/iden3/go-backup/ff"
)



type Claim struct {
	Data [N_ELEMENTS]uint64
}

var Claims *Claim

// Retrieve claims (received, not part form Merkle Tree)
func GetRxClaims() *Claim {
	return Claims
}

// Dummy data init functions
func initClaims() *Claim {
	var test_data Claim
	for i := 0; i < N_ELEMENTS; i++ {
		test_data.Data[i] = uint64(rand.Intn(1234567)) //1234567123453
	}
	return &test_data
}

/// ZKP
type ZKP struct {
	R *Claim
	L *WalletConfig
}

var ZKPData *ZKP

func initZKP() *ZKP {
	var zkp ZKP
	zkp.R = initClaims()
	zkp.L = initWalletConfig()

	return &zkp
}

// MT
type MT struct {
	Y [N_ELEMENTS]*Claim
}

var MerkleTree *MT

// Retrieve MerkleTree
func GetMerkleTreeSnapshot() *MT {
	return MerkleTree
}

func initMerkleTree() *MT {
	var mt MT
	for i := 0; i < N_ELEMENTS; i++ {
		mt.Y[i] = initClaims()
	}

	return &mt
}

///// Other
//  Generate Key
func KeyOperational() []byte {
	key, _ := ff.NewElement(PRIME)
	key.SetRandom().ToMont()

	return key.ToByte()
}

// Generate Genesis ID
func NewID() []byte {
	id, err := genRandomBytes(ID_LEN)
	if err != nil {
		panic(err)
	}
	return id
}



