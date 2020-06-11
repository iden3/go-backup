/*
 Generic wrapper for goff ff library.

 To add more element types, download goff (https://github.com/iden3/goff)
   go run goff -m 21888242871839275222246405745257275088548364400416034343698204186575808495617 -o ./ff -p ff -e element_bn256p -i Element

   This will generate a new element element_bnp256p in folder ff that can be used by this wrapper

  goff fork applies some changes to templates:
   - Supports 32 bit architectures (changes done in BigInt conversion utilities)
   - Supports generated ff packages to be included in an interface
*/

package ff

import (
	"errors"
	"math/big"
	"strconv"
)

//interface to describe Finite Field
type Element interface {
	GetUint64() []uint64
	SetUint64(v uint64) Element
	SetFromArray(x []uint64) Element
	Set(x Element) Element
	SetZero() Element
	SetOne() Element
	Neg(x Element) Element
	Div(x, y Element) Element
	Equal(x Element) bool
	IsZero() bool
	Inverse(x Element) Element
	SetRandom() Element
	One() Element
	Add(x, y Element) Element
	AddAssign(x Element) Element
	Double(x Element) Element
	Sub(x, y Element) Element
	SubAssign(x Element) Element
	Exp(x Element, exponent ...uint64) Element
	FromMont() Element
	ToMont() Element
	ToRegular() Element
	String() string
	ToByte() []byte
	FromByte(x []byte) Element
	ToBigInt(res *big.Int) *big.Int
	ToBigIntRegular(res *big.Int) *big.Int
	SetBigInt(v *big.Int) Element
	SetString(s string) Element
	Legendre() int
	Sqrt(x Element) Element
	Mul(x, y Element) Element
	MulAssign(x Element) Element
	Square(x Element) Element
}

// Type of FF defined
const (
	// 21888242871839275222246405745257275088696311157297823662689037894645226208583
	FF_BN256_FQ = iota
	//21888242871839275222246405745257275088548364400416034343698204186575808495617
	FF_BN256_FP
	// Add more primes
)

const (
	DEFAULT_PRIME = FF_BN256_FP
)

// Create new  Finite Field Element depending on type
func NewElement(t int) (Element, error) {
	switch t {
	case FF_BN256_FQ:
		var el element_bn256q
		return &el, nil

	case FF_BN256_FP:
		var el element_bn256p
		return &el, nil

	default:
		return nil, errors.New("Invalid FF type")
	}
}

// FromInterface converts i1 from uint64, int, string, or element_bn256p, big.Int into element_
// panic if provided type is not supported
func FromInterface(i1 interface{}, t int) (Element, error) {
	val, err := NewElement(t)

	if err != nil {
		return nil, err
	}

	switch c1 := i1.(type) {
	case uint64:
		val.SetUint64(c1)
	case int:
		val.SetString(strconv.Itoa(c1))
	case string:
		val.SetString(c1)
	case big.Int:
		val.SetBigInt(&c1)
	case Element:
		val = c1
	default:
		return nil, errors.New("Invaid i1 provided")
	}

	return val, nil
}

// Check if Element belongs to a known type
func IsValid(element_type int) bool {
	switch element_type {
	case FF_BN256_FP:
		return true

	case FF_BN256_FQ:
		return true

	default:
		return false
	}

}

// Returns number of bits in element
func Msb(el Element) int {
	n := el.ToRegular().GetUint64()
	for idx := len(n)*64 - 1; idx >= 0; idx -= 1 {
		word := int(idx / 64)
		bit := idx % 64
		if (n[word]>>bit)&0x1 == 1 {
			return idx
		}
	}
	return 0
}

// Retrieves bit b from Element
func Bit(el Element, b int) int {
	n := el.ToRegular().GetUint64()
	word := int(b / 64)
	bit := b % 64
	return int((n[word] >> bit) & 0x1)
}
