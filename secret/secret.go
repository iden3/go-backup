package secret

import (
	"github.com/iden3/go-backup/ff"
)

type Share struct {
	Px int
	Py ff.Element
}

// Interface to describe Secret Sharing :
type SecretSharer interface {
	GenerateSecret(shares []Share) (ff.Element, error)
	GenerateShares(ff.Element) ([]Share, error)
	GetMinShares() int
	GetMaxShares() int
	GetElType() int
}

// Secret Sharing protocols implemented
const (
	SS_SHAMIR = iota
	SS_NSECRET
)
