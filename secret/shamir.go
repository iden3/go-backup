package secret

import (
	"errors"
	"github.com/iden3/go-backup/ff"
	"math"
)

// Define shamir configuration:
// MinShares   -> minimum number of shares to generate secret
// MaxShares   -> maximum number of shares distributed
// ElementType -> defines prime
type Shamir struct {
	MinShares   int
	MaxShares   int
	ElementType int
}

// Generate secret from shares S[0],...,S[N-1], where S[i] = (sx[i], sy[i]) = (x, poly(x))
// secret = Sum_fromj=0_to_N-1   sy[j]   *    Prod_from_m=0,m!=j_to_m=N-1 ( sx[m] / (sx[m] - sx[j]))
//  sx[i] is an integer, sy[i] is a FF in Montgomery
func (s Shamir) GenerateSecret(shares []Share) (ff.Element, error) {
	secret, _ := ff.NewElement(s.ElementType)
	nFF, _ := ff.NewElement(s.ElementType)
	dFF, _ := ff.NewElement(s.ElementType)
	lFF, _ := ff.NewElement(s.ElementType)
	var xm, xj int

	for _, share1 := range shares {
		jidx := share1.Px
		lFF.SetOne()
		for _, share2 := range shares {
			midx := share2.Px
			if midx == jidx {
				continue
			}
			xm = midx
			xj = jidx
			nFF.SetUint64(uint64(xm))
			if xm > xj {
				dFF.SetUint64(uint64(xm - xj))
			} else {
				dFF.SetUint64(uint64(xj - xm))
				dFF.Neg(dFF)
			}
			dFF.Inverse(dFF)
			nFF.MulAssign(dFF)
			lFF.MulAssign(nFF)
		}
		lFF.MulAssign(share1.Py)
		secret.AddAssign(lFF)
	}

	return secret, nil
}

// Generate shares in Montgomery
// for a given poly p(x), generate N shares (N=MaxShares) s[1], s[1],...,s[N]
// such that s[i] = p(i) for  0 < i < N and  s[0] = secret (s[0] is not a share) is in Regular fmt
func (s Shamir) GenerateShares(secret ff.Element) ([]Share, error) {

	shares := make([]Share, 0)
	val := 0.0

	//initialize Poly. Coefficients are in Montgomery
	poly := s.generatePoly()

	// Generate all shares
	for idx := 1; idx <= s.MaxShares; idx++ {
		tmpFF, _ := ff.NewElement(s.ElementType)

		// FF Element storing share y-coordinate
		py, _ := ff.NewElement(s.ElementType)
		newShare := Share{
			Px: idx,
			Py: py.Set(secret),
		}

		for coeffIdx, coeff := range poly {
			val = math.Pow(float64(idx), float64(coeffIdx+1))
			tmpFF.SetUint64(uint64(val))
			tmpFF.MulAssign(coeff)
			newShare.Py.AddAssign(tmpFF)
		}
		shares = append(shares, newShare)
	}

	return shares, nil
}

// Initialize Shamir's secret sharing configuration
func (cfg *Shamir) NewConfig(minShares, maxShares, elementType int) error {
	var err error

	// check args are correct before initializing config
	if minShares == 0 {
		err = errors.New("Shamir's Secret Config : Minimum shares needs to be > 0")
		return err
	}
	if minShares > maxShares {
		err = errors.New("Shamir's Secret Config : Minimum shares needs to be <= than Maximum shares")
		return err
	}
	if ff.IsValid(elementType) == false {
		err = errors.New("Shamir's Secret Config : Finite Field unknown")
		return err
	}

	cfg.MinShares = minShares
	cfg.MaxShares = maxShares
	cfg.ElementType = elementType

	return nil
}

// Generate new secret
func (s Shamir) NewSecret() ff.Element {
	secret, _ := ff.NewElement(s.ElementType)
	secret.SetRandom().ToMont()
	return secret
}

// Generate random coefficients a[1]...a[MinShares-1] in Montgomery belonging to Finite Field
// f(x) = secret + a[1] * x + a[2] * x^2 + ... + a[MinShares-1] * x^(MinShares-1)
// secret not included in poly
func (s Shamir) generatePoly() []ff.Element {
	poly := make([]ff.Element, s.MinShares-1)
	for coeffIdx := range poly {
		poly[coeffIdx], _ = ff.NewElement(s.ElementType)
		poly[coeffIdx].SetRandom().ToMont()
	}

	return poly
}

func (s Shamir) GetMinShares() int {
	return s.MinShares
}
func (s Shamir) GetMaxShares() int {
	return s.MaxShares
}
func (s Shamir) GetElType() int {
	return s.ElementType
}
