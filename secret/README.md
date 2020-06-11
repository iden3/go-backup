
# Secret
Secret Sharing library. Defines interface *SecretSharer* with the following methods:
-	GenerateSecret(shares []Share) (ff.Element, error)
-	GenerateShares(ff.Element) ([]Share, error)
-	GetMinShares() int
-	GetMaxShares() int
-	GetElType() int

*shamir* implements Shamir's Secret Sharing  a form of secret sharing, where a secret is divided into parts, giving each participant its own unique part.

To reconstruct the original secret, a minimum number of parts is required. In the threshold scheme this number is less than the total number of parts. Otherwise all participants are needed to reconstruct the original secret

*shamir* uses Finite Field elements defined in ff

For more information, read https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing

*shamir* implements *SecretSharer* interface.


## Example
```
import (
	"fmt"
	"github.com/iden3/go-backup/ff"
)


min_shares := 3
max_shares := 6
prime := ff.FF_BN256_FP

var cfg Shamir

// Initialize Shamir's configuration 
//   generate 6 shares, 3 required to retrieve secret
err := cfg.NewConfig(min_shares, max_shares, ff.FF_BN256_FP)
if err != nil {
	fmt.Errorf("Incorrect Shamir's configuration")
}

// Generate New Secret
secret := cfg.NewSecret()


// Generate Shares from secret
shares, err := cfg.GenerateShares(secret)
if err != nil {
	fmt.Errorf("Ereror generating shares")
}

// Regenerate secret from 3 shares
recovered_secret, err := cfg.GenerateSecret(shares[0:2])

if !secret.Equal(recovered_secret) {
	fmt.Errorf("Secrets are not equal")
}
```