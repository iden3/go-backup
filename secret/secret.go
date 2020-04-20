package secret

import (
         "github.com/iden3/go-backup/ff"
)


type Secret struct {
   X   map[uint64]ff.Element
}

// Interface to describe Secret Sharing :
type SecretSharer interface {
    GenerateSecret(shares map[uint64]ff.Element)    (ff.Element, error) 
    GenerateShares(ff.Element) (map[uint64]ff.Element, error)
    GetMinShares() int
    GetMaxShares() int 
    GetElType() int
}

// Secret Sharing protocols implemented
const (
        SS_SHAMIR = iota
        SS_NSECRET
)

