package ff

import (
	"testing"
)

func TestFFOK(t *testing.T) {
	el, err := NewElement(FF_BN256_FP)
	el.SetRandom()
	a := el.ToByte()
	a[0] += 1
	el.FromByte(a)
	el.One()

	if err != nil {
		t.Error(err)
	}

	if !IsValid(FF_BN256_FP) {
		t.Error("Element is invalid ")
	}

	_, err = NewElement(FF_BN256_FQ)
	if err != nil {
		t.Error(err)
	}

	if !IsValid(FF_BN256_FQ) {
		t.Error("Element is invalid ")
	}

	_, err = FromInterface("123454542342", FF_BN256_FP)
	if err != nil {
		t.Error(err)
	}

	if IsValid(FF_BN256_FQ + 12) {
		t.Error("Element is invalid ")
	}

}
