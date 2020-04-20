package secret

import (
         "testing"
         "fmt"
         "github.com/iden3/go-backup/ff"
         "math/rand"
)

func TestShamirOK(t *testing.T) {
   // Generate Shamir config
   var min_shares, max_shares, prime = 3, 6, ff.FF_BN256_PRIME
   var cfg Shamir
   err  := cfg.NewConfig(min_shares, max_shares, ff.FF_BN256_PRIME)
   if err != nil{
      t.Error(err)
   }
   fmt.Println("Config : ",cfg)

   // Secret
   secret, err1 := ff.NewElement(prime)
   if err1 != nil{
      t.Error(err1)
   }
   secret.SetRandom().ToMont()
   fmt.Println("Secret : ", secret)

   // Generate Shares
   shares, err2 := cfg.GenerateShares(secret)
   if err2 != nil{
      t.Error(err2)
   }
   
   // select shares to regenerate secret
   for iter :=0; iter< 10; iter++ {
     selected_shares := shuffleShares(shares, prime, min_shares, max_shares)
     fmt.Printf("\nIteration : %d\n",iter)
     //fmt.Println("Selected Shares ", selected_shares)

     // generate key
     new_secret, err3 := cfg.GenerateSecret(selected_shares)
     if err3 != nil{
        t.Error(err3)
     }
     if  !secret.Equal(new_secret){
        t.Error("Secrets not equal")
     } else {
        fmt.Println("Secrets are equal (OK)")
     }
   }
}

func TestShamirKO(t *testing.T) {
   // Generate Shamir config
   var min_shares, max_shares, prime = 3, 6, ff.FF_BN256_PRIME
   var cfg Shamir
   err  := cfg.NewConfig(min_shares, max_shares, ff.FF_BN256_PRIME)
   if err != nil{
      t.Error(err)
   }
   fmt.Println("Config : ",cfg)

   // Secret
   secret, err1 := ff.NewElement(prime)
   if err1 != nil{
      t.Error(err1)
   }
   secret.SetRandom().ToMont()
   fmt.Println("Secret : ", secret)

   // Generate Shares
   shares, err2 := cfg.GenerateShares(secret)
   if err2 != nil{
      t.Error(err2)
   }
   
   // select insufficient shares to regenerate secret
   for iter :=0; iter< 10; iter++ {
     selected_shares := shuffleShares(shares, prime, min_shares-1, max_shares)
     fmt.Printf("\nIteration : %d\n",iter)
     //fmt.Println("Selected Shares ", selected_shares)

     // generate key
     new_secret, err3 := cfg.GenerateSecret(selected_shares)
     if err3 != nil{
        t.Error(err3)
     }
     if  !secret.Equal(new_secret){
        fmt.Println("Secrets are not equal (OK)")
     } else {
        t.Error("Secrets are equal")
     }
   }
}

func shuffleShares(pool map[uint64]ff.Element, prime, n, max int) map[uint64]ff.Element {
   selected := make(map[uint64]ff.Element)
   for i := 0 ; i < n; i++ {
      found := true
      for found {
         found = false
         new_idx := uint64(rand.Intn(max)+1)
         for idx  := range(selected) {
            if idx == new_idx{
              found = true
              continue
            }
         }
         if !found {
           selected[new_idx], _ = ff.NewElement(prime)
           selected[new_idx].Set(pool[new_idx])
         }
      }
   }
   return selected
}
