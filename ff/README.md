# ff
Finite Field Arithmetic library based on goff (https://github.com/ConsenSys/goff)

## Overview
Defines *Element* interface with the following methods implemented by elements created by goff:
-	GetUint64() []uint64
-	SetUint64(v uint64) Element
-	SetFromArray(x []uint64) Element
-	Set(x Element) Element
-	SetZero() Element
-	SetOne() Element
-	Neg(x Element) Element
-	Div(x, y Element) Element
-	Equal(x Element) bool
-	IsZero() bool
-	Inverse(x Element) Element
-	SetRandom() Element
-	One() Element
-	Add(x, y Element) Element
-	AddAssign(x Element) Element
-	Double(x Element) Element
-	Sub(x, y Element) Element
-	SubAssign(x Element) Element
-	Exp(x Element, exponent ...uint64) Element
-	FromMont() Element
-	ToMont() Element
-	ToRegular() Element
-	String() string
-	ToByte() []byte
-	FromByte(x []byte) Element
-	ToBigInt(res *big.Int) *big.Int
-	ToBigIntRegular(res *big.Int) *big.Int
-	SetBigInt(v *big.Int) Element
-	SetString(s string) Element
-	Legendre() int
-	Sqrt(x Element) Element
-	Mul(x, y Element) Element
-	MulAssign(x Element) Element
-	Square(x Element) Element

## Adding Additional Elements

To add an additional Element :
```
go install github.com/iden3/goff
go run goff -m 21888242871839275222246405745257275088548364400416034343698204186575808495617 -o ./ff -p ff -e element_bn256p -i Element
```

This command will include *element_bn256p* in directory ./ff implementing intereface *Element*

## Elements defined
Currently, there are two elements defined:

FF_BN256_FQ  for field defined by prime 21888242871839275222246405745257275088696311157297823662689037894645226208583

FF_BN256_FP for field defined by prime	21888242871839275222246405745257275088548364400416034343698204186575808495617
	
## Example

```
el1, err := NewElement(FF_BN256_FP)
el1.SetRandom()
    
el2, err := NewElement(FF_BN256_FP)
el2.SetRandom()

el1.Add(el1, el2)

```




