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

import (
	"crypto/rand"
	"math/big"
	mrand "math/rand"
	"testing"
)

func TestELEMENT_BN256PCorrectnessAgainstBigInt(t *testing.T) {
	modulus, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	cmpEandB := func(e *element_bn256p, b *big.Int, name string) {
		var _e big.Int
		if e.FromMont().ToBigInt(&_e).Cmp(b) != 0 {
			t.Fatal(name, "failed")
		}
	}
	var modulusMinusOne, one big.Int
	one.SetUint64(1)

	modulusMinusOne.Sub(modulus, &one)

	var n int
	if testing.Short() {
		n = 20
	} else {
		n = 500
	}

	sAdx := supportAdx

	for i := 0; i < n; i++ {
		if i == n/2 && sAdx {
			supportAdx = false // testing without adx instruction
		}
		// sample 2 random big int
		b1, _ := rand.Int(rand.Reader, modulus)
		b2, _ := rand.Int(rand.Reader, modulus)
		rExp := mrand.Uint64()

		// adding edge cases
		// TODO need more edge cases
		switch i {
		case 0:
			rExp = 0
			b1.SetUint64(0)
		case 1:
			b2.SetUint64(0)
		case 2:
			b1.SetUint64(0)
			b2.SetUint64(0)
		case 3:
			rExp = 0
		case 4:
			rExp = 1
		case 5:
			rExp = ^uint64(0) // max uint
		case 6:
			rExp = 2
			b1.Set(&modulusMinusOne)
		case 7:
			b2.Set(&modulusMinusOne)
		case 8:
			b1.Set(&modulusMinusOne)
			b2.Set(&modulusMinusOne)
		}

		rbExp := new(big.Int).SetUint64(rExp)

		var bMul, bAdd, bSub, bDiv, bNeg, bLsh, bInv, bExp, bExp2, bSquare big.Int

		// e1 = mont(b1), e2 = mont(b2)
		var e1, e2, eMul, eAdd, eSub, eDiv, eNeg, eLsh, eInv, eExp, eSquare, eMulAssign, eSubAssign, eAddAssign element_bn256p
		e1.SetBigInt(b1)
		e2.SetBigInt(b2)

		// (e1*e2).FromMont() === b1*b2 mod q ... etc
		eSquare.Square(&e1)
		eMul.Mul(&e1, &e2)
		eMulAssign.Set(&e1)
		eMulAssign.MulAssign(&e2)
		eAdd.Add(&e1, &e2)
		eAddAssign.Set(&e1)
		eAddAssign.AddAssign(&e2)
		eSub.Sub(&e1, &e2)
		eSubAssign.Set(&e1)
		eSubAssign.SubAssign(&e2)
		eDiv.Div(&e1, &e2)
		eNeg.Neg(&e1)
		eInv.Inverse(&e1)
		eExp.Exp(&e1, rExp)

		eLsh.Double(&e1)

		// same operations with big int
		bAdd.Add(b1, b2).Mod(&bAdd, modulus)
		bMul.Mul(b1, b2).Mod(&bMul, modulus)
		bSquare.Mul(b1, b1).Mod(&bSquare, modulus)
		bSub.Sub(b1, b2).Mod(&bSub, modulus)
		bDiv.ModInverse(b2, modulus)
		bDiv.Mul(&bDiv, b1).
			Mod(&bDiv, modulus)
		bNeg.Neg(b1).Mod(&bNeg, modulus)

		bInv.ModInverse(b1, modulus)
		bExp.Exp(b1, rbExp, modulus)
		bLsh.Lsh(b1, 1).Mod(&bLsh, modulus)

		cmpEandB(&eSquare, &bSquare, "Square")
		cmpEandB(&eMul, &bMul, "Mul")
		cmpEandB(&eMulAssign, &bMul, "MulAssign")
		cmpEandB(&eAdd, &bAdd, "Add")
		cmpEandB(&eAddAssign, &bAdd, "AddAssign")
		cmpEandB(&eSub, &bSub, "Sub")
		cmpEandB(&eSubAssign, &bSub, "SubAssign")
		cmpEandB(&eDiv, &bDiv, "Div")
		cmpEandB(&eNeg, &bNeg, "Neg")
		cmpEandB(&eInv, &bInv, "Inv")
		cmpEandB(&eExp, &bExp, "Exp")

		cmpEandB(&eLsh, &bLsh, "Lsh")

		// legendre symbol
		if e1.Legendre() != big.Jacobi(b1, modulus) {
			t.Fatal("legendre symbol computation failed")
		}
		if e2.Legendre() != big.Jacobi(b2, modulus) {
			t.Fatal("legendre symbol computation failed")
		}

		// these are slow, killing circle ci
		if n <= 5 {
			// sqrt
			var eSqrt, eExp2 element_bn256p
			var bSqrt big.Int
			bSqrt.ModSqrt(b1, modulus)
			eSqrt.Sqrt(&e1)
			cmpEandB(&eSqrt, &bSqrt, "Sqrt")

			bits := b2.Bits()
			exponent := make([]uint64, len(bits))
			for k := 0; k < len(bits); k++ {
				exponent[k] = uint64(bits[k])
			}
			eExp2.Exp(&e1, exponent...)

			bExp2.Exp(b1, b2, modulus)
			cmpEandB(&eExp2, &bExp2, "Exp multi words")
		}
	}
	supportAdx = sAdx
}

func TestELEMENT_BN256PIsRandom(t *testing.T) {
	for i := 0; i < 50; i++ {
		var x, y element_bn256p
		x.SetRandom()
		y.SetRandom()
		if x.Equal(&y) {
			t.Fatal("2 random numbers are unlikely to be equal")
		}
	}
}

// -------------------------------------------------------------------------------------------------
// benchmarks
// most benchmarks are rudimentary and should sample a large number of random inputs
// or be run multiple times to ensure it didn't measure the fastest path of the function

var benchReselement_bn256p element_bn256p

func BenchmarkInverseELEMENT_BN256P(b *testing.B) {
	var x element_bn256p
	x.SetRandom()
	benchReselement_bn256p.SetRandom()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		benchReselement_bn256p.Inverse(&x)
	}

}
func BenchmarkExpELEMENT_BN256P(b *testing.B) {
	var x element_bn256p
	x.SetRandom()
	benchReselement_bn256p.SetRandom()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchReselement_bn256p.Exp(&x, mrand.Uint64())

	}
}

func BenchmarkDoubleELEMENT_BN256P(b *testing.B) {
	benchReselement_bn256p.SetRandom()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchReselement_bn256p.Double(&benchReselement_bn256p)
	}
}

func BenchmarkAddELEMENT_BN256P(b *testing.B) {
	var x element_bn256p
	x.SetRandom()
	benchReselement_bn256p.SetRandom()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchReselement_bn256p.Add(&x, &benchReselement_bn256p)
	}
}

func BenchmarkSubELEMENT_BN256P(b *testing.B) {
	var x element_bn256p
	x.SetRandom()
	benchReselement_bn256p.SetRandom()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchReselement_bn256p.Sub(&x, &benchReselement_bn256p)
	}
}

func BenchmarkNegELEMENT_BN256P(b *testing.B) {
	benchReselement_bn256p.SetRandom()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchReselement_bn256p.Neg(&benchReselement_bn256p)
	}
}

func BenchmarkDivELEMENT_BN256P(b *testing.B) {
	var x element_bn256p
	x.SetRandom()
	benchReselement_bn256p.SetRandom()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchReselement_bn256p.Div(&x, &benchReselement_bn256p)
	}
}

func BenchmarkFromMontELEMENT_BN256P(b *testing.B) {
	benchReselement_bn256p.SetRandom()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchReselement_bn256p.FromMont()
	}
}

func BenchmarkToMontELEMENT_BN256P(b *testing.B) {
	benchReselement_bn256p.SetRandom()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchReselement_bn256p.ToMont()
	}
}
func BenchmarkSquareELEMENT_BN256P(b *testing.B) {
	benchReselement_bn256p.SetRandom()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchReselement_bn256p.Square(&benchReselement_bn256p)
	}
}

func BenchmarkSqrtELEMENT_BN256P(b *testing.B) {
	var a element_bn256p
	a.SetRandom()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchReselement_bn256p.Sqrt(&a)
	}
}

func BenchmarkMulAssignELEMENT_BN256P(b *testing.B) {
	x := element_bn256p{
		1997599621687373223,
		6052339484930628067,
		10108755138030829701,
		150537098327114917,
	}
	benchReselement_bn256p.SetOne()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchReselement_bn256p.MulAssign(&x)
	}
}
