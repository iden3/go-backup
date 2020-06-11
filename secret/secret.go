package secret

import (
        "encoding/binary"

	"github.com/iden3/go-backup/ff"
)

const (
      PX_OFFSET = 0
      PY_OFFSET = 8
      FFTYPE_OFFSET   = 40
      SHARE_SIZE = 41
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

func (s Share) Marshal(p int) []byte {
   b := make([]byte, SHARE_SIZE)
   binary.LittleEndian.PutUint64(b[PX_OFFSET:PY_OFFSET], uint64(s.Px))
   copy(b[PY_OFFSET:FFTYPE_OFFSET] , s.Py.ToByte())
   b[FFTYPE_OFFSET] = byte(p)
   

   return b
}

func (s *Share)Unmarshal(b []byte) (*Share, error) {
   var err error
   s.Px = int(binary.LittleEndian.Uint64(b[PX_OFFSET:PY_OFFSET]))
   p := int(b[FFTYPE_OFFSET])
   s.Py, err = ff.NewElement(p)
   if err != nil {
     return nil, err
   }
   s.Py = s.Py.FromByte(b[PY_OFFSET:FFTYPE_OFFSET])

   return s, nil
}

// Secret Sharing protocols implemented
const (
	SS_SHAMIR = iota
	SS_NSECRET
)

