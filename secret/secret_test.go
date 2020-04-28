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
     selected_shares := shuffleShares(shares, min_shares)
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
     selected_shares := shuffleShares(shares, min_shares-1)
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

func shuffleShares(pool []Share, n int) []Share {
   selected := make([]Share, 0)
   nshares := len(pool)
   for i := 0 ; i < n; i++ {
      found := true
      for found {
         found = false
         new_idx := rand.Intn(nshares)
         for _, share := range(selected) {
            if share.Px == pool[new_idx].Px {
              found = true
              continue
            }
         }
         if !found {
           selected = append(selected, pool[new_idx])
         }
      }
   }
   return selected
}
