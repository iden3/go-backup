package ff

import(
         "testing"
         "fmt"
)


func TestFFOK(t *testing.T){
    el, err := NewElement(FF_BN256_PRIME)
    fmt.Println(el.SetRandom())
    a := el.ToByte()
    fmt.Println(a)
    a[0] += 1
    fmt.Println(el.FromByte(a))
    fmt.Println(el)
    fmt.Println(el.One())
    fmt.Println(el)

    if err != nil{
       t.Error(err)
    }

    if !IsValid(FF_BN256_PRIME) {
       t.Error("Element is invalid ")
    }
    
    _, err = NewElement(FF_BN256_ORDER)
    if err != nil{
       t.Error(err)
    }

    if !IsValid(FF_BN256_ORDER) {
       t.Error("Element is invalid ")
    }

    _, err = FromInterface("123454542342",FF_BN256_PRIME)
    if err != nil{
       t.Error(err)
    }

    if IsValid(FF_BN256_ORDER+12) {
       t.Error("Element is invalid ")
    }


}
