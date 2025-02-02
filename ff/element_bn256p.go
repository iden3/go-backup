// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by goff (v0.2.2) DO NOT EDIT

// Package ff contains field arithmetic operations
package ff

// /!\ WARNING /!\
// this code has not been audited and is provided as-is. In particular,
// there is no security guarantees such as constant time implementation
// or side-channel attack resistance
// /!\ WARNING /!\

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"math/bits"
	"sync"
	"unsafe"
)

// element_bn256p represents a field element stored on 4 words (uint64)
// element_bn256p are assumed to be in Montgomery form in all methods
// field modulus q =
//
// 21888242871839275222246405745257275088548364400416034343698204186575808495617
type element_bn256p [4]uint64

// element_bn256pLimbs number of 64 bits words needed to represent element_bn256p
const element_bn256pLimbs = 4

// element_bn256pBits number bits needed to represent element_bn256p
const element_bn256pBits = 254

// GetUint64 returns z[0],... z[N-1]
func (z element_bn256p) GetUint64() []uint64 {
	return z[0:]
}

// SetUint64 z = v, sets z LSB to v (non-Montgomery form) and convert z to Montgomery form
func (z *element_bn256p) SetUint64(v uint64) Element {

	z[0] = v
	z[1] = 0
	z[2] = 0
	z[3] = 0
	return z.ToMont()
}

// Set z = x
func (z *element_bn256p) Set(x Element) Element {

	var xar = x.GetUint64()
	z[0] = xar[0]
	z[1] = xar[1]
	z[2] = xar[2]
	z[3] = xar[3]
	return z
}

// Set z = x
func (z *element_bn256p) SetFromArray(xar []uint64) Element {

	z[0] = xar[0]
	z[1] = xar[1]
	z[2] = xar[2]
	z[3] = xar[3]
	return z.ToMont()
}

// SetZero z = 0
func (z *element_bn256p) SetZero() Element {

	z[0] = 0
	z[1] = 0
	z[2] = 0
	z[3] = 0
	return z
}

// SetOne z = 1 (in Montgomery form)
func (z *element_bn256p) SetOne() Element {

	z[0] = 12436184717236109307
	z[1] = 3962172157175319849
	z[2] = 7381016538464732718
	z[3] = 1011752739694698287
	return z
}

// Neg z = q - x
func (z *element_bn256p) Neg(x Element) Element {

	if x.IsZero() {
		return z.SetZero()
	}
	var borrow uint64
	var xar = x.GetUint64()
	z[0], borrow = bits.Sub64(4891460686036598785, xar[0], 0)
	z[1], borrow = bits.Sub64(2896914383306846353, xar[1], borrow)
	z[2], borrow = bits.Sub64(13281191951274694749, xar[2], borrow)
	z[3], _ = bits.Sub64(3486998266802970665, xar[3], borrow)
	return z
}

// Div z = x*y^-1 mod q
func (z *element_bn256p) Div(x, y Element) Element {

	var yInv element_bn256p
	yInv.Inverse(y)
	z.Mul(x, &yInv)
	return z
}

// Equal returns z == x
func (z *element_bn256p) Equal(x Element) bool {

	var xar = x.GetUint64()
	return (z[3] == xar[3]) && (z[2] == xar[2]) && (z[1] == xar[1]) && (z[0] == xar[0])
}

// IsZero returns z == 0
func (z *element_bn256p) IsZero() bool {
	return (z[3] | z[2] | z[1] | z[0]) == 0
}

// field modulus stored as big.Int
var _element_bn256pModulus big.Int
var onceelement_bn256pModulus sync.Once

func element_bn256pModulus() *big.Int {
	onceelement_bn256pModulus.Do(func() {
		_element_bn256pModulus.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	})
	return &_element_bn256pModulus
}

// Inverse z = x^-1 mod q
// Algorithm 16 in "Efficient Software-Implementation of Finite Fields with Applications to Cryptography"
// if x == 0, sets and returns z = x
func (z *element_bn256p) Inverse(x Element) Element {

	if x.IsZero() {
		return z.Set(x)
	}

	// initialize u = q
	var u = element_bn256p{
		4891460686036598785,
		2896914383306846353,
		13281191951274694749,
		3486998266802970665,
	}

	// initialize s = r^2
	var s = element_bn256p{
		1997599621687373223,
		6052339484930628067,
		10108755138030829701,
		150537098327114917,
	}

	// r = 0
	r := element_bn256p{}

	v := x.GetUint64()

	var carry, borrow, t, t2 uint64
	var bigger, uIsOne, vIsOne bool

	for !uIsOne && !vIsOne {
		for v[0]&1 == 0 {

			// v = v >> 1
			t2 = v[3] << 63
			v[3] >>= 1
			t = t2
			t2 = v[2] << 63
			v[2] = (v[2] >> 1) | t
			t = t2
			t2 = v[1] << 63
			v[1] = (v[1] >> 1) | t
			t = t2
			v[0] = (v[0] >> 1) | t

			if s[0]&1 == 1 {

				// s = s + q
				s[0], carry = bits.Add64(s[0], 4891460686036598785, 0)
				s[1], carry = bits.Add64(s[1], 2896914383306846353, carry)
				s[2], carry = bits.Add64(s[2], 13281191951274694749, carry)
				s[3], _ = bits.Add64(s[3], 3486998266802970665, carry)

			}

			// s = s >> 1
			t2 = s[3] << 63
			s[3] >>= 1
			t = t2
			t2 = s[2] << 63
			s[2] = (s[2] >> 1) | t
			t = t2
			t2 = s[1] << 63
			s[1] = (s[1] >> 1) | t
			t = t2
			s[0] = (s[0] >> 1) | t

		}
		for u[0]&1 == 0 {

			// u = u >> 1
			t2 = u[3] << 63
			u[3] >>= 1
			t = t2
			t2 = u[2] << 63
			u[2] = (u[2] >> 1) | t
			t = t2
			t2 = u[1] << 63
			u[1] = (u[1] >> 1) | t
			t = t2
			u[0] = (u[0] >> 1) | t

			if r[0]&1 == 1 {

				// r = r + q
				r[0], carry = bits.Add64(r[0], 4891460686036598785, 0)
				r[1], carry = bits.Add64(r[1], 2896914383306846353, carry)
				r[2], carry = bits.Add64(r[2], 13281191951274694749, carry)
				r[3], _ = bits.Add64(r[3], 3486998266802970665, carry)

			}

			// r = r >> 1
			t2 = r[3] << 63
			r[3] >>= 1
			t = t2
			t2 = r[2] << 63
			r[2] = (r[2] >> 1) | t
			t = t2
			t2 = r[1] << 63
			r[1] = (r[1] >> 1) | t
			t = t2
			r[0] = (r[0] >> 1) | t

		}

		// v >= u
		bigger = !(v[3] < u[3] || (v[3] == u[3] && (v[2] < u[2] || (v[2] == u[2] && (v[1] < u[1] || (v[1] == u[1] && (v[0] < u[0])))))))

		if bigger {

			// v = v - u
			v[0], borrow = bits.Sub64(v[0], u[0], 0)
			v[1], borrow = bits.Sub64(v[1], u[1], borrow)
			v[2], borrow = bits.Sub64(v[2], u[2], borrow)
			v[3], _ = bits.Sub64(v[3], u[3], borrow)

			// r >= s
			bigger = !(r[3] < s[3] || (r[3] == s[3] && (r[2] < s[2] || (r[2] == s[2] && (r[1] < s[1] || (r[1] == s[1] && (r[0] < s[0])))))))

			if bigger {

				// s = s + q
				s[0], carry = bits.Add64(s[0], 4891460686036598785, 0)
				s[1], carry = bits.Add64(s[1], 2896914383306846353, carry)
				s[2], carry = bits.Add64(s[2], 13281191951274694749, carry)
				s[3], _ = bits.Add64(s[3], 3486998266802970665, carry)

			}

			// s = s - r
			s[0], borrow = bits.Sub64(s[0], r[0], 0)
			s[1], borrow = bits.Sub64(s[1], r[1], borrow)
			s[2], borrow = bits.Sub64(s[2], r[2], borrow)
			s[3], _ = bits.Sub64(s[3], r[3], borrow)

		} else {

			// u = u - v
			u[0], borrow = bits.Sub64(u[0], v[0], 0)
			u[1], borrow = bits.Sub64(u[1], v[1], borrow)
			u[2], borrow = bits.Sub64(u[2], v[2], borrow)
			u[3], _ = bits.Sub64(u[3], v[3], borrow)

			// s >= r
			bigger = !(s[3] < r[3] || (s[3] == r[3] && (s[2] < r[2] || (s[2] == r[2] && (s[1] < r[1] || (s[1] == r[1] && (s[0] < r[0])))))))

			if bigger {

				// r = r + q
				r[0], carry = bits.Add64(r[0], 4891460686036598785, 0)
				r[1], carry = bits.Add64(r[1], 2896914383306846353, carry)
				r[2], carry = bits.Add64(r[2], 13281191951274694749, carry)
				r[3], _ = bits.Add64(r[3], 3486998266802970665, carry)

			}

			// r = r - s
			r[0], borrow = bits.Sub64(r[0], s[0], 0)
			r[1], borrow = bits.Sub64(r[1], s[1], borrow)
			r[2], borrow = bits.Sub64(r[2], s[2], borrow)
			r[3], _ = bits.Sub64(r[3], s[3], borrow)

		}
		uIsOne = (u[0] == 1) && (u[3]|u[2]|u[1]) == 0
		vIsOne = (v[0] == 1) && (v[3]|v[2]|v[1]) == 0
	}

	if uIsOne {
		z.Set(&r)
	} else {
		z.Set(&s)
	}

	return z
}

// SetRandom sets z to a random element < q
func (z *element_bn256p) SetRandom() Element {

	bytes := make([]byte, 32)
	io.ReadFull(rand.Reader, bytes)
	z[0] = binary.BigEndian.Uint64(bytes[0:8])
	z[1] = binary.BigEndian.Uint64(bytes[8:16])
	z[2] = binary.BigEndian.Uint64(bytes[16:24])
	z[3] = binary.BigEndian.Uint64(bytes[24:32])
	z[3] %= 3486998266802970665

	// if z > q --> z -= q
	// note: this is NOT constant time
	if !(z[3] < 3486998266802970665 || (z[3] == 3486998266802970665 && (z[2] < 13281191951274694749 || (z[2] == 13281191951274694749 && (z[1] < 2896914383306846353 || (z[1] == 2896914383306846353 && (z[0] < 4891460686036598785))))))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 4891460686036598785, 0)
		z[1], b = bits.Sub64(z[1], 2896914383306846353, b)
		z[2], b = bits.Sub64(z[2], 13281191951274694749, b)
		z[3], _ = bits.Sub64(z[3], 3486998266802970665, b)
	}

	return z
}

// One returns 1 (in montgommery form)
func (z element_bn256p) One() Element {

	one := z
	one.SetOne()
	return &one
}

// Add z = x + y mod q
func (z *element_bn256p) Add(x, y Element) Element {

	var carry uint64
	var xar, yar = x.GetUint64(), y.GetUint64()

	z[0], carry = bits.Add64(xar[0], yar[0], 0)
	z[1], carry = bits.Add64(xar[1], yar[1], carry)
	z[2], carry = bits.Add64(xar[2], yar[2], carry)
	z[3], _ = bits.Add64(xar[3], yar[3], carry)

	// if z > q --> z -= q
	// note: this is NOT constant time
	if !(z[3] < 3486998266802970665 || (z[3] == 3486998266802970665 && (z[2] < 13281191951274694749 || (z[2] == 13281191951274694749 && (z[1] < 2896914383306846353 || (z[1] == 2896914383306846353 && (z[0] < 4891460686036598785))))))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 4891460686036598785, 0)
		z[1], b = bits.Sub64(z[1], 2896914383306846353, b)
		z[2], b = bits.Sub64(z[2], 13281191951274694749, b)
		z[3], _ = bits.Sub64(z[3], 3486998266802970665, b)
	}
	return z
}

// AddAssign z = z + x mod q
func (z *element_bn256p) AddAssign(x Element) Element {

	var carry uint64
	var xar = x.GetUint64()

	z[0], carry = bits.Add64(z[0], xar[0], 0)
	z[1], carry = bits.Add64(z[1], xar[1], carry)
	z[2], carry = bits.Add64(z[2], xar[2], carry)
	z[3], _ = bits.Add64(z[3], xar[3], carry)

	// if z > q --> z -= q
	// note: this is NOT constant time
	if !(z[3] < 3486998266802970665 || (z[3] == 3486998266802970665 && (z[2] < 13281191951274694749 || (z[2] == 13281191951274694749 && (z[1] < 2896914383306846353 || (z[1] == 2896914383306846353 && (z[0] < 4891460686036598785))))))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 4891460686036598785, 0)
		z[1], b = bits.Sub64(z[1], 2896914383306846353, b)
		z[2], b = bits.Sub64(z[2], 13281191951274694749, b)
		z[3], _ = bits.Sub64(z[3], 3486998266802970665, b)
	}
	return z
}

// Double z = x + x mod q, aka Lsh 1
func (z *element_bn256p) Double(x Element) Element {

	var carry uint64
	var xar = x.GetUint64()

	z[0], carry = bits.Add64(xar[0], xar[0], 0)
	z[1], carry = bits.Add64(xar[1], xar[1], carry)
	z[2], carry = bits.Add64(xar[2], xar[2], carry)
	z[3], _ = bits.Add64(xar[3], xar[3], carry)

	// if z > q --> z -= q
	// note: this is NOT constant time
	if !(z[3] < 3486998266802970665 || (z[3] == 3486998266802970665 && (z[2] < 13281191951274694749 || (z[2] == 13281191951274694749 && (z[1] < 2896914383306846353 || (z[1] == 2896914383306846353 && (z[0] < 4891460686036598785))))))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 4891460686036598785, 0)
		z[1], b = bits.Sub64(z[1], 2896914383306846353, b)
		z[2], b = bits.Sub64(z[2], 13281191951274694749, b)
		z[3], _ = bits.Sub64(z[3], 3486998266802970665, b)
	}
	return z
}

// Sub  z = x - y mod q
func (z *element_bn256p) Sub(x, y Element) Element {

	var b uint64
	var xar, yar = x.GetUint64(), y.GetUint64()
	z[0], b = bits.Sub64(xar[0], yar[0], 0)
	z[1], b = bits.Sub64(xar[1], yar[1], b)
	z[2], b = bits.Sub64(xar[2], yar[2], b)
	z[3], b = bits.Sub64(xar[3], yar[3], b)
	if b != 0 {
		var c uint64
		z[0], c = bits.Add64(z[0], 4891460686036598785, 0)
		z[1], c = bits.Add64(z[1], 2896914383306846353, c)
		z[2], c = bits.Add64(z[2], 13281191951274694749, c)
		z[3], _ = bits.Add64(z[3], 3486998266802970665, c)
	}
	return z
}

// SubAssign  z = z - x mod q
func (z *element_bn256p) SubAssign(x Element) Element {

	var b uint64
	var xar = x.GetUint64()
	z[0], b = bits.Sub64(z[0], xar[0], 0)
	z[1], b = bits.Sub64(z[1], xar[1], b)
	z[2], b = bits.Sub64(z[2], xar[2], b)
	z[3], b = bits.Sub64(z[3], xar[3], b)
	if b != 0 {
		var c uint64
		z[0], c = bits.Add64(z[0], 4891460686036598785, 0)
		z[1], c = bits.Add64(z[1], 2896914383306846353, c)
		z[2], c = bits.Add64(z[2], 13281191951274694749, c)
		z[3], _ = bits.Add64(z[3], 3486998266802970665, c)
	}
	return z
}

// Exp z = x^exponent mod q
// (not optimized)
// exponent (non-montgomery form) is ordered from least significant word to most significant word
func (z *element_bn256p) Exp(x Element, exponent ...uint64) Element {

	r := 0
	msb := 0
	for i := len(exponent) - 1; i >= 0; i-- {
		if exponent[i] == 0 {
			r++
		} else {
			msb = (i * 64) + bits.Len64(exponent[i])
			break
		}
	}
	exponent = exponent[:len(exponent)-r]
	if len(exponent) == 0 {
		return z.SetOne()
	}
	z.Set(x)

	l := msb - 2
	for i := l; i >= 0; i-- {
		z.Square(z)
		if exponent[i/64]&(1<<uint(i%64)) != 0 {
			z.MulAssign(x)

		}
	}
	return z
}

// FromMont converts z in place (i.e. mutates) from Montgomery to regular representation
// sets and returns z = z * 1
func (z *element_bn256p) FromMont() Element {

	fromMontelement_bn256p(z)
	return z
}

// ToMont converts z to Montgomery form
// sets and returns z = z * r^2
func (z *element_bn256p) ToMont() Element {

	var rSquare = element_bn256p{
		1997599621687373223,
		6052339484930628067,
		10108755138030829701,
		150537098327114917,
	}
	mulAssignelement_bn256p(z, &rSquare)
	return z
}

// ToRegular returns z in regular form (doesn't mutate z)
func (z element_bn256p) ToRegular() Element {
	return z.FromMont()

}

// String returns the string form of an element_bn256p in Montgomery form
func (z *element_bn256p) String() string {
	var _z big.Int
	return z.ToBigIntRegular(&_z).String()
}

// ToByte returns the byte form of an element_bn256p in Regular form
func (z element_bn256p) ToByte() []byte {
	t := z.ToRegular().(*element_bn256p)

	var _z []byte
	_z1 := make([]byte, 8)
	binary.LittleEndian.PutUint64(_z1, t[0])
	_z = append(_z, _z1...)
	binary.LittleEndian.PutUint64(_z1, t[1])
	_z = append(_z, _z1...)
	binary.LittleEndian.PutUint64(_z1, t[2])
	_z = append(_z, _z1...)
	binary.LittleEndian.PutUint64(_z1, t[3])
	_z = append(_z, _z1...)
	return _z
}

// FromByte returns the byte form of an element_bn256p in Regular form (mutates z)
func (z *element_bn256p) FromByte(x []byte) Element {

	z[0] = binary.LittleEndian.Uint64(x[0*8 : (0+1)*8])
	z[1] = binary.LittleEndian.Uint64(x[1*8 : (1+1)*8])
	z[2] = binary.LittleEndian.Uint64(x[2*8 : (2+1)*8])
	z[3] = binary.LittleEndian.Uint64(x[3*8 : (3+1)*8])
	return z.ToMont()
}

// ToBigInt returns z as a big.Int in Montgomery form
func (z *element_bn256p) ToBigInt(res *big.Int) *big.Int {
	if bits.UintSize == 64 {
		bits := (*[4]big.Word)(unsafe.Pointer(z))
		return res.SetBits(bits[:])
	} else {
		var bits [4 * 2]big.Word
		bits[0*2] = big.Word(z[0])
		bits[0*2+1] = big.Word(z[0] >> 32)
		bits[1*2] = big.Word(z[1])
		bits[1*2+1] = big.Word(z[1] >> 32)
		bits[2*2] = big.Word(z[2])
		bits[2*2+1] = big.Word(z[2] >> 32)
		bits[3*2] = big.Word(z[3])
		bits[3*2+1] = big.Word(z[3] >> 32)
		return res.SetBits(bits[:])
	}
}

// ToBigIntRegular returns z as a big.Int in regular form
func (z element_bn256p) ToBigIntRegular(res *big.Int) *big.Int {
	if bits.UintSize == 64 {
		z.FromMont()
		bits := (*[4]big.Word)(unsafe.Pointer(&z))
		return res.SetBits(bits[:])
	} else {
		var bits [4 * 2]big.Word
		bits[0*2] = big.Word(z[0])
		bits[0*2+1] = big.Word(z[0] >> 32)
		bits[1*2] = big.Word(z[1])
		bits[1*2+1] = big.Word(z[1] >> 32)
		bits[2*2] = big.Word(z[2])
		bits[2*2+1] = big.Word(z[2] >> 32)
		bits[3*2] = big.Word(z[3])
		bits[3*2+1] = big.Word(z[3] >> 32)
		return res.SetBits(bits[:])
	}
}

// SetBigInt sets z to v (regular form) and returns z in Montgomery form
func (z *element_bn256p) SetBigInt(v *big.Int) Element {

	z.SetZero()

	zero := big.NewInt(0)
	q := element_bn256pModulus()

	// fast path
	c := v.Cmp(q)
	if c == 0 {
		return z
	} else if c != 1 && v.Cmp(zero) != -1 {
		// v should
		vBits := v.Bits()
		for i := 0; i < len(vBits); i++ {
			z[i] = uint64(vBits[i])
		}
		return z.ToMont()
	}

	// copy input
	vv := new(big.Int).Set(v)
	vv.Mod(v, q)

	// v should
	vBits := vv.Bits()
	if bits.UintSize == 64 {
		for i := 0; i < len(vBits); i++ {
			z[i] = uint64(vBits[i])
		}
	} else {
		for i := 0; i < len(vBits); i++ {
			if i%2 == 0 {
				z[i/2] = uint64(vBits[i])
			} else {
				z[i/2] |= uint64(vBits[i]) << 32
			}
		}
	}
	return z.ToMont()
}

// SetString creates a big.Int with s (in base 10) and calls SetBigInt on z
func (z *element_bn256p) SetString(s string) Element {

	x, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("element_bn256p.SetString failed -> can't parse number in base10 into a big.Int")
	}
	return z.SetBigInt(x)
}

// Legendre returns the Legendre symbol of z (either +1, -1, or 0.)
func (z *element_bn256p) Legendre() int {
	var l element_bn256p
	// z^((q-1)/2)
	l.Exp(z,
		11669102379873075200,
		10671829228508198984,
		15863968012492123182,
		1743499133401485332,
	)

	if l.IsZero() {
		return 0
	}

	// if l == 1
	if (l[3] == 1011752739694698287) && (l[2] == 7381016538464732718) && (l[1] == 3962172157175319849) && (l[0] == 12436184717236109307) {
		return 1
	}
	return -1
}

// Sqrt z = √x mod q
// if the square root doesn't exist (x is not a square mod q)
// Sqrt leaves z unchanged and returns nil
func (z *element_bn256p) Sqrt(x Element) Element {

	// q ≡ 1 (mod 4)
	// see modSqrtTonelliShanks in math/big/int.go
	// using https://www.maa.org/sites/default/files/pdf/upload_library/22/Polya/07468342.di020786.02p0470a.pdf

	var y, b, t, w element_bn256p
	// w = x^((s-1)/2))
	w.Exp(x,
		14829091926808964255,
		867720185306366531,
		688207751544974772,
		6495040407,
	)

	// y = x^((s+1)/2)) = w * x
	y.Mul(x, &w)

	// b = x^s = w * w * x = y * x
	b.Mul(&w, &y)

	// g = nonResidue ^ s
	var g = element_bn256p{
		7164790868263648668,
		11685701338293206998,
		6216421865291908056,
		1756667274303109607,
	}
	r := uint64(28)

	// compute legendre symbol
	// t = x^((q-1)/2) = r-1 squaring of x^s
	t = b
	for i := uint64(0); i < r-1; i++ {
		t.Square(&t)
	}
	if t.IsZero() {
		return z.SetZero()
	}
	if !((t[3] == 1011752739694698287) && (t[2] == 7381016538464732718) && (t[1] == 3962172157175319849) && (t[0] == 12436184717236109307)) {
		// t != 1, we don't have a square root
		return nil
	}
	for {
		var m uint64
		t = b

		// for t != 1
		for !((t[3] == 1011752739694698287) && (t[2] == 7381016538464732718) && (t[1] == 3962172157175319849) && (t[0] == 12436184717236109307)) {
			t.Square(&t)
			m++
		}

		if m == 0 {
			return z.Set(&y)
		}
		// t = g^(2^(r-m-1)) mod q
		ge := int(r - m - 1)
		t = g
		for ge > 0 {
			t.Square(&t)
			ge--
		}

		g.Square(&t)
		y.MulAssign(&t)
		b.MulAssign(&g)
		r = m
	}
}
