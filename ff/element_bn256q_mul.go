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

import "math/bits"

// Mul z = x * y mod q
// see https://hackmd.io/@zkteam/modular_multiplication
func (z *element_bn256q) Mul(x, y Element) Element {

	var xar, yar = x.GetUint64(), y.GetUint64()

	var t [4]uint64
	var c [3]uint64
	{
		// round 0
		v := xar[0]
		c[1], c[0] = bits.Mul64(v, yar[0])
		m := c[0] * 9786893198990664585
		c[2] = madd0(m, 4332616871279656263, c[0])
		c[1], c[0] = madd1(v, yar[1], c[1])
		c[2], t[0] = madd2(m, 10917124144477883021, c[2], c[0])
		c[1], c[0] = madd1(v, yar[2], c[1])
		c[2], t[1] = madd2(m, 13281191951274694749, c[2], c[0])
		c[1], c[0] = madd1(v, yar[3], c[1])
		t[3], t[2] = madd3(m, 3486998266802970665, c[0], c[2], c[1])
	}
	{
		// round 1
		v := xar[1]
		c[1], c[0] = madd1(v, yar[0], t[0])
		m := c[0] * 9786893198990664585
		c[2] = madd0(m, 4332616871279656263, c[0])
		c[1], c[0] = madd2(v, yar[1], c[1], t[1])
		c[2], t[0] = madd2(m, 10917124144477883021, c[2], c[0])
		c[1], c[0] = madd2(v, yar[2], c[1], t[2])
		c[2], t[1] = madd2(m, 13281191951274694749, c[2], c[0])
		c[1], c[0] = madd2(v, yar[3], c[1], t[3])
		t[3], t[2] = madd3(m, 3486998266802970665, c[0], c[2], c[1])
	}
	{
		// round 2
		v := xar[2]
		c[1], c[0] = madd1(v, yar[0], t[0])
		m := c[0] * 9786893198990664585
		c[2] = madd0(m, 4332616871279656263, c[0])
		c[1], c[0] = madd2(v, yar[1], c[1], t[1])
		c[2], t[0] = madd2(m, 10917124144477883021, c[2], c[0])
		c[1], c[0] = madd2(v, yar[2], c[1], t[2])
		c[2], t[1] = madd2(m, 13281191951274694749, c[2], c[0])
		c[1], c[0] = madd2(v, yar[3], c[1], t[3])
		t[3], t[2] = madd3(m, 3486998266802970665, c[0], c[2], c[1])
	}
	{
		// round 3
		v := xar[3]
		c[1], c[0] = madd1(v, yar[0], t[0])
		m := c[0] * 9786893198990664585
		c[2] = madd0(m, 4332616871279656263, c[0])
		c[1], c[0] = madd2(v, yar[1], c[1], t[1])
		c[2], z[0] = madd2(m, 10917124144477883021, c[2], c[0])
		c[1], c[0] = madd2(v, yar[2], c[1], t[2])
		c[2], z[1] = madd2(m, 13281191951274694749, c[2], c[0])
		c[1], c[0] = madd2(v, yar[3], c[1], t[3])
		z[3], z[2] = madd3(m, 3486998266802970665, c[0], c[2], c[1])
	}

	// if z > q --> z -= q
	// note: this is NOT constant time
	if !(z[3] < 3486998266802970665 || (z[3] == 3486998266802970665 && (z[2] < 13281191951274694749 || (z[2] == 13281191951274694749 && (z[1] < 10917124144477883021 || (z[1] == 10917124144477883021 && (z[0] < 4332616871279656263))))))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 4332616871279656263, 0)
		z[1], b = bits.Sub64(z[1], 10917124144477883021, b)
		z[2], b = bits.Sub64(z[2], 13281191951274694749, b)
		z[3], _ = bits.Sub64(z[3], 3486998266802970665, b)
	}
	return z
}

// MulAssign z = z * x mod q
// see https://hackmd.io/@zkteam/modular_multiplication
func (z *element_bn256q) MulAssign(x Element) Element {

	var xar = x.GetUint64()

	var t [4]uint64
	var c [3]uint64
	{
		// round 0
		v := z[0]
		c[1], c[0] = bits.Mul64(v, xar[0])
		m := c[0] * 9786893198990664585
		c[2] = madd0(m, 4332616871279656263, c[0])
		c[1], c[0] = madd1(v, xar[1], c[1])
		c[2], t[0] = madd2(m, 10917124144477883021, c[2], c[0])
		c[1], c[0] = madd1(v, xar[2], c[1])
		c[2], t[1] = madd2(m, 13281191951274694749, c[2], c[0])
		c[1], c[0] = madd1(v, xar[3], c[1])
		t[3], t[2] = madd3(m, 3486998266802970665, c[0], c[2], c[1])
	}
	{
		// round 1
		v := z[1]
		c[1], c[0] = madd1(v, xar[0], t[0])
		m := c[0] * 9786893198990664585
		c[2] = madd0(m, 4332616871279656263, c[0])
		c[1], c[0] = madd2(v, xar[1], c[1], t[1])
		c[2], t[0] = madd2(m, 10917124144477883021, c[2], c[0])
		c[1], c[0] = madd2(v, xar[2], c[1], t[2])
		c[2], t[1] = madd2(m, 13281191951274694749, c[2], c[0])
		c[1], c[0] = madd2(v, xar[3], c[1], t[3])
		t[3], t[2] = madd3(m, 3486998266802970665, c[0], c[2], c[1])
	}
	{
		// round 2
		v := z[2]
		c[1], c[0] = madd1(v, xar[0], t[0])
		m := c[0] * 9786893198990664585
		c[2] = madd0(m, 4332616871279656263, c[0])
		c[1], c[0] = madd2(v, xar[1], c[1], t[1])
		c[2], t[0] = madd2(m, 10917124144477883021, c[2], c[0])
		c[1], c[0] = madd2(v, xar[2], c[1], t[2])
		c[2], t[1] = madd2(m, 13281191951274694749, c[2], c[0])
		c[1], c[0] = madd2(v, xar[3], c[1], t[3])
		t[3], t[2] = madd3(m, 3486998266802970665, c[0], c[2], c[1])
	}
	{
		// round 3
		v := z[3]
		c[1], c[0] = madd1(v, xar[0], t[0])
		m := c[0] * 9786893198990664585
		c[2] = madd0(m, 4332616871279656263, c[0])
		c[1], c[0] = madd2(v, xar[1], c[1], t[1])
		c[2], z[0] = madd2(m, 10917124144477883021, c[2], c[0])
		c[1], c[0] = madd2(v, xar[2], c[1], t[2])
		c[2], z[1] = madd2(m, 13281191951274694749, c[2], c[0])
		c[1], c[0] = madd2(v, xar[3], c[1], t[3])
		z[3], z[2] = madd3(m, 3486998266802970665, c[0], c[2], c[1])
	}

	// if z > q --> z -= q
	// note: this is NOT constant time
	if !(z[3] < 3486998266802970665 || (z[3] == 3486998266802970665 && (z[2] < 13281191951274694749 || (z[2] == 13281191951274694749 && (z[1] < 10917124144477883021 || (z[1] == 10917124144477883021 && (z[0] < 4332616871279656263))))))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 4332616871279656263, 0)
		z[1], b = bits.Sub64(z[1], 10917124144477883021, b)
		z[2], b = bits.Sub64(z[2], 13281191951274694749, b)
		z[3], _ = bits.Sub64(z[3], 3486998266802970665, b)
	}
	return z
}
func mulAssignelement_bn256q(z, x Element) {

	var xar = x.GetUint64()
	var zar = z.GetUint64()

	var t [4]uint64
	var c [3]uint64
	{
		// round 0
		v := zar[0]
		c[1], c[0] = bits.Mul64(v, xar[0])
		m := c[0] * 9786893198990664585
		c[2] = madd0(m, 4332616871279656263, c[0])
		c[1], c[0] = madd1(v, xar[1], c[1])
		c[2], t[0] = madd2(m, 10917124144477883021, c[2], c[0])
		c[1], c[0] = madd1(v, xar[2], c[1])
		c[2], t[1] = madd2(m, 13281191951274694749, c[2], c[0])
		c[1], c[0] = madd1(v, xar[3], c[1])
		t[3], t[2] = madd3(m, 3486998266802970665, c[0], c[2], c[1])
	}
	{
		// round 1
		v := zar[1]
		c[1], c[0] = madd1(v, xar[0], t[0])
		m := c[0] * 9786893198990664585
		c[2] = madd0(m, 4332616871279656263, c[0])
		c[1], c[0] = madd2(v, xar[1], c[1], t[1])
		c[2], t[0] = madd2(m, 10917124144477883021, c[2], c[0])
		c[1], c[0] = madd2(v, xar[2], c[1], t[2])
		c[2], t[1] = madd2(m, 13281191951274694749, c[2], c[0])
		c[1], c[0] = madd2(v, xar[3], c[1], t[3])
		t[3], t[2] = madd3(m, 3486998266802970665, c[0], c[2], c[1])
	}
	{
		// round 2
		v := zar[2]
		c[1], c[0] = madd1(v, xar[0], t[0])
		m := c[0] * 9786893198990664585
		c[2] = madd0(m, 4332616871279656263, c[0])
		c[1], c[0] = madd2(v, xar[1], c[1], t[1])
		c[2], t[0] = madd2(m, 10917124144477883021, c[2], c[0])
		c[1], c[0] = madd2(v, xar[2], c[1], t[2])
		c[2], t[1] = madd2(m, 13281191951274694749, c[2], c[0])
		c[1], c[0] = madd2(v, xar[3], c[1], t[3])
		t[3], t[2] = madd3(m, 3486998266802970665, c[0], c[2], c[1])
	}
	{
		// round 3
		v := zar[3]
		c[1], c[0] = madd1(v, xar[0], t[0])
		m := c[0] * 9786893198990664585
		c[2] = madd0(m, 4332616871279656263, c[0])
		c[1], c[0] = madd2(v, xar[1], c[1], t[1])
		c[2], zar[0] = madd2(m, 10917124144477883021, c[2], c[0])
		c[1], c[0] = madd2(v, xar[2], c[1], t[2])
		c[2], zar[1] = madd2(m, 13281191951274694749, c[2], c[0])
		c[1], c[0] = madd2(v, xar[3], c[1], t[3])
		zar[3], zar[2] = madd3(m, 3486998266802970665, c[0], c[2], c[1])
	}

	// if z > q --> z -= q
	// note: this is NOT constant time
	if !(zar[3] < 3486998266802970665 || (zar[3] == 3486998266802970665 && (zar[2] < 13281191951274694749 || (zar[2] == 13281191951274694749 && (zar[1] < 10917124144477883021 || (zar[1] == 10917124144477883021 && (zar[0] < 4332616871279656263))))))) {
		var b uint64
		zar[0], b = bits.Sub64(zar[0], 4332616871279656263, 0)
		zar[1], b = bits.Sub64(zar[1], 10917124144477883021, b)
		zar[2], b = bits.Sub64(zar[2], 13281191951274694749, b)
		zar[3], _ = bits.Sub64(zar[3], 3486998266802970665, b)
	}
	z.SetFromArray(zar)
}

func fromMontelement_bn256q(z *element_bn256q) {
	// the following lines implement z = z * 1
	// with a modified CIOS montgomery multiplication
	{
		// m = z[0]n'[0] mod W
		m := z[0] * 9786893198990664585
		C := madd0(m, 4332616871279656263, z[0])
		C, z[0] = madd2(m, 10917124144477883021, z[1], C)
		C, z[1] = madd2(m, 13281191951274694749, z[2], C)
		C, z[2] = madd2(m, 3486998266802970665, z[3], C)
		z[3] = C
	}
	{
		// m = z[0]n'[0] mod W
		m := z[0] * 9786893198990664585
		C := madd0(m, 4332616871279656263, z[0])
		C, z[0] = madd2(m, 10917124144477883021, z[1], C)
		C, z[1] = madd2(m, 13281191951274694749, z[2], C)
		C, z[2] = madd2(m, 3486998266802970665, z[3], C)
		z[3] = C
	}
	{
		// m = z[0]n'[0] mod W
		m := z[0] * 9786893198990664585
		C := madd0(m, 4332616871279656263, z[0])
		C, z[0] = madd2(m, 10917124144477883021, z[1], C)
		C, z[1] = madd2(m, 13281191951274694749, z[2], C)
		C, z[2] = madd2(m, 3486998266802970665, z[3], C)
		z[3] = C
	}
	{
		// m = z[0]n'[0] mod W
		m := z[0] * 9786893198990664585
		C := madd0(m, 4332616871279656263, z[0])
		C, z[0] = madd2(m, 10917124144477883021, z[1], C)
		C, z[1] = madd2(m, 13281191951274694749, z[2], C)
		C, z[2] = madd2(m, 3486998266802970665, z[3], C)
		z[3] = C
	}

	// if z > q --> z -= q
	// note: this is NOT constant time
	if !(z[3] < 3486998266802970665 || (z[3] == 3486998266802970665 && (z[2] < 13281191951274694749 || (z[2] == 13281191951274694749 && (z[1] < 10917124144477883021 || (z[1] == 10917124144477883021 && (z[0] < 4332616871279656263))))))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 4332616871279656263, 0)
		z[1], b = bits.Sub64(z[1], 10917124144477883021, b)
		z[2], b = bits.Sub64(z[2], 13281191951274694749, b)
		z[3], _ = bits.Sub64(z[3], 3486998266802970665, b)
	}
}

// for test purposes
func reduceelement_bn256q(z *element_bn256q) {

	// if z > q --> z -= q
	// note: this is NOT constant time
	if !(z[3] < 3486998266802970665 || (z[3] == 3486998266802970665 && (z[2] < 13281191951274694749 || (z[2] == 13281191951274694749 && (z[1] < 10917124144477883021 || (z[1] == 10917124144477883021 && (z[0] < 4332616871279656263))))))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 4332616871279656263, 0)
		z[1], b = bits.Sub64(z[1], 10917124144477883021, b)
		z[2], b = bits.Sub64(z[2], 13281191951274694749, b)
		z[3], _ = bits.Sub64(z[3], 3486998266802970665, b)
	}
}
