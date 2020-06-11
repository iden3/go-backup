package secret

import (
	"errors"
	"github.com/iden3/go-backup/ff"
	"math"
)

// Define shamir configuration:
// Min_shares   -> minimum number of shares to generate secret
// Max_shares   -> maximum number of shares distributed
// Element_type -> defines prime
type Shamir struct {
	Min_shares   int
	Max_shares   int
	Element_type int
}

// Generate secret from shares S[0],...,S[N-1], where S[i] = (sx[i], sy[i]) = (x, poly(x))
// secret = Sum_fromj=0_to_N-1   sy[j]   *    Prod_from_m=0,m!=j_to_m=N-1 ( sx[m] / (sx[m] - sx[j]))
//  sx[i] is an integer, sy[i] is a FF in Montgomery
func (s Shamir) GenerateSecret(shares []Share) (ff.Element, error) {
	secret, _ := ff.NewElement(s.Element_type)
	n_ff, _ := ff.NewElement(s.Element_type)
	d_ff, _ := ff.NewElement(s.Element_type)
	l_ff, _ := ff.NewElement(s.Element_type)
	var xm, xj int

	for _, share1 := range shares {
		jidx := share1.Px
		l_ff.SetOne()
		for _, share2 := range shares {
			midx := share2.Px
			if midx == jidx {
				continue
			}
			xm = midx
			xj = jidx
			n_ff.SetUint64(uint64(xm))
			if xm > xj {
				d_ff.SetUint64(uint64(xm - xj))
			} else {
				d_ff.SetUint64(uint64(xj - xm))
				d_ff.Neg(d_ff)
			}
			d_ff.Inverse(d_ff)
			n_ff.MulAssign(d_ff)
			l_ff.MulAssign(n_ff)
		}
		l_ff.MulAssign(share1.Py)
		secret.AddAssign(l_ff)
	}

	return secret, nil
}

// Generate shares in Montgomery
// for a given poly p(x), generate N shares (N=Max_shares) s[1], s[1],...,s[N]
// such that s[i] = p(i) for  0 < i < N and  s[0] = secret (s[0] is not a share) is in Regular fmt
func (s Shamir) GenerateShares(secret ff.Element) ([]Share, error) {

	shares := make([]Share, 0)
	val := 0.0

	//initialize Poly. Coefficients are in Montgomery
	poly := s.generatePoly()

	// Generate all shares
	for idx := 1; idx <= s.Max_shares; idx++ {
		tmp_ff, _ := ff.NewElement(s.Element_type)

		// FF Element storing share y-coordinate
		py, _ := ff.NewElement(s.Element_type)
		new_share := Share{
			Px: idx,
			Py: py.Set(secret),
		}

		for coeff_idx, coeff := range poly {
			val = math.Pow(float64(idx), float64(coeff_idx+1))
			tmp_ff.SetUint64(uint64(val))
			tmp_ff.MulAssign(coeff)
			new_share.Py.AddAssign(tmp_ff)
		}
		shares = append(shares, new_share)
	}

	return shares, nil
}

// Initialize Shamir's secret sharing configuration
func (cfg *Shamir) NewConfig(min_shares, max_shares, element_type int) error {
	var err error

	// check args are correct before initializing config
	if min_shares == 0 {
		err = errors.New("Shamir's Secret Config : Minimum shares needs to be > 0")
		return err
	}
	if min_shares > max_shares {
		err = errors.New("Shamir's Secret Config : Minimum shares needs to be <= than Maximum shares")
		return err
	}
	if ff.IsValid(element_type) == false {
		err = errors.New("Shamir's Secret Config : Finite Field unknown")
		return err
	}

	cfg.Min_shares = min_shares
	cfg.Max_shares = max_shares
	cfg.Element_type = element_type

	return nil
}

// Generate new secret
func (s Shamir) NewSecret() ff.Element {
	secret, _ := ff.NewElement(s.Element_type)
	secret.SetRandom().ToMont()
        return secret
}

// Generate random coefficients a[1]...a[Min_shares-1] in Montgomery belonging to Finite Field
// f(x) = secret + a[1] * x + a[2] * x^2 + ... + a[Min_shares-1] * x^(Min_shares-1)
// secret not included in poly
func (s Shamir) generatePoly() []ff.Element {
	poly := make([]ff.Element, s.Min_shares-1)
	for coeff_idx := range poly {
		poly[coeff_idx], _ = ff.NewElement(s.Element_type)
		poly[coeff_idx].SetRandom().ToMont()
	}

	return poly
}

func (s Shamir) GetMinShares() int {
	return s.Min_shares
}
func (s Shamir) GetMaxShares() int {
	return s.Max_shares
}
func (s Shamir) GetElType() int {
	return s.Element_type
}
