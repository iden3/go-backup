/*
  Collection of support functions that emulate  go-iden3-core functionality
*/
package main

import (
        "github.com/iden3/go-backup/ff"
)

// Auxiliary information emulating claims, ZKP and Merkle Tree (these types are defined 
// somewhere in core library)
// Strcuture and contents are not important. Just deinfing some arbitrary data structures
// to do backup
type  Claim struct{
    Data     [N_ELEMENTS]uint64
}

type ZKP struct {
     R   *Claim
     L   *WalletConfig
}

type MT struct {
    Y  [N_ELEMENTS]*Claim
}

var claims *Claim
var zKPData *ZKP
var merkleTree *MT

//  Generate Key
func KeyOperational() []byte{
   key, _ := ff.NewElement(PRIME)
   key.SetRandom().ToMont()
   
   return key.ToByte()
}

// Generate Genesis ID
func NewID() []byte{
    id, err := genRandomBytes(ID_LEN)
    if  err  != nil {
       panic(err)
    }
    return id
}

// Retrieve MerkleTree
func GetMerkleTreeSnapshot() *MT {
   return merkleTree
}

// Retrieve claims (received, not part form Merkle Tree)
func GetRxClaims() *Claim{
   return claims
}

// Retrieve generated ZKP
func GetZKP() *ZKP {
   return zKPData
}


