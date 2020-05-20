///// Encoding Layer

package backuplib

import (
	"bufio"
	"encoding/gob"
	"errors"
	"github.com/iden3/go-backup/ff"
	fc "github.com/iden3/go-backup/filecrypt"
	"github.com/iden3/go-backup/secret"
	"github.com/iden3/go-iden3-core/db"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"io/ioutil"
	"os"
)

// Types of data we can include in the backup. Needed to register the data strcuture
const (
	START_TYPES = iota
	WALLET_CONFIG
	CUSTODIAN
	SSHARING
	SHARES
	PKEYS
	STORAGE
	NTYPES
	// Add other possible data types that we need encoding
)

func initEncoding() {
	for i := START_TYPES + 1; i < NTYPES; i++ {
		encodeType(i)
	}
}

// Register data strucrure
func encodeType(dtype int) {
	switch dtype {

	case WALLET_CONFIG:
		gob.Register(&WalletConfig{})

	case CUSTODIAN:
		gob.Register(&Custodians{})
		var el []Custodian
		gob.Register(el)

	case SSHARING:
		gob.Register(&secret.Shamir{})

	case SHARES:
		el1, _ := ff.NewElement(PRIME)
		var el2 secret.Share
		var el3 []secret.Share
		gob.Register(el1)
		gob.Register(el2)
		gob.Register(el3)

	case PKEYS:
		var el PrivateKeys
		var el1 *babyjub.PrivateKey
		gob.Register(&el)
		gob.Register(el1)

	case STORAGE:
		var el db.KV
		var el1 []db.KV
		gob.Register(&el)
		gob.Register(el1)

	}
}

// Transform share encoding to string
func encodeShareToString(shares []secret.Share, folder string) string {
	tmp_fname := folder + "share-tmp.dat"
	encodeShare(shares, tmp_fname)
	defer os.Remove(tmp_fname)

	// Read file with share as as a bytestream and convert it to string
	share_bytes, err := ioutil.ReadFile(tmp_fname)
	if err != nil {
		panic(err)
	}
	share_string := string(share_bytes)

	return share_string
}

// Transform share encoding to []byte
func encodeShareToByte(shares []secret.Share, folder string) []byte {
	tmp_fname := folder + "share-tmp.dat"
	encodeShare(shares, tmp_fname)
	defer os.Remove(tmp_fname)
	data := readBinaryFile(tmp_fname)

	return data
}

// Read file
func readBinaryFile(tmp_fname string) []byte {
	file, err := os.Open(tmp_fname)
	defer file.Close()

	if err != nil {
		panic(err)
	}

	stats, err := file.Stat()
	if err != nil {
		panic(err)
	}

	var size int64 = stats.Size()
	bytes := make([]byte, size)

	bufr := bufio.NewReader(file)
	_, err = bufr.Read(bytes)

	return bytes
}

// Generate share blocks to distribure via secret sharing and return
// filecrpyt bytestream
func encodeShare(shares []secret.Share, fname string) {
	// Key header -> no key
	hdr_k := &fc.NoKeyFc{}
	err := hdr_k.FillHdr(fc.FC_HDR_VERSION_1, fc.FC_KEY_T_NOKEY)
	if err != nil {
		panic(err)
	}
	// Encryption header -> not encrypted
	hdr_e := &fc.ClearFc{}
	err = hdr_e.FillHdr(fc.FC_HDR_VERSION_1, fc.FC_CLEAR,
		fc.FC_BSIZE_BYTES_256, fc.FC_HDR_BIDX_SINGLE)
	if err != nil {
		panic(err)
	}
	// filecrypt only outputs a file. At some point, functionality should be extended
	// to also generate a string
	err = fc.Encrypt(hdr_k, hdr_e, fname, shares)
	if err != nil {
		panic(err)
	}
}

// Decode and decrypt file using provided key
func DecodeUnencrypted(fname string) error {
	info := decode(fname, nil)

	rx_custodians := retrieveCustodians(info)

	if rx_custodians == nil {
		return errors.New("Invalid Custodian Format")
	} else {
		initCustodians()
		custodians := GetCustodians()
		custodians.Data = rx_custodians
		SetCustodians(custodians)
	}

	rx_secret_cfg := retrieveSSharing(info)

	if rx_secret_cfg == nil {
		return errors.New("Invalid Secret Sharing Format")
	} else {
		initSecretCfg()
		secret_cfg := GetSecretCfg()
		secret_cfg.Min_shares = rx_secret_cfg.GetMinShares()
		secret_cfg.Max_shares = rx_secret_cfg.GetMaxShares()
		secret_cfg.Element_type = rx_secret_cfg.GetElType()
		SetSecretCfg(secret_cfg)
	}

	return nil
}

func DecodeEncrypted(fname string) error {
	key := GetkOp()
	info := decode(fname, key)

	retrieved_wallet := retrieveWallet(info)
	if retrieved_wallet == nil {
		return errors.New("Invalid Wallet Format")
	} else {
		SetWallet(retrieved_wallet)
	}

	retrieved_shares := retrieveShares(info)
	if retrieved_shares == nil {
		return errors.New("Invalid shares Format")
	} else {
		shares := GetShares()
		shares.Data = fromShares(retrieved_shares)
		SetShares(shares)
	}

	retrieved_private_keys := retrievePrivateKeys(info)
	if retrieved_private_keys == nil {
		return errors.New("Invalid Private Keys Format")
	} else {
		SetPrivateKeys(retrieved_private_keys)
	}

	retrieved_storage := retrieveStorage(info)
	if retrieved_storage == nil {
		return errors.New("Invalid Storage Format")
	} else {
		SetStorage(retrieved_storage)
	}

	return nil

}

// Decode and decrypt file using provided key
func decode(fname string, key []byte) []interface{} {
	results, _ := fc.Decrypt(fname, key)

	return results

}

// Retrieve functions return a specific data type from a generic type

// retrieve Custodian data structure
func retrieveCustodians(info []interface{}) []Custodian {
	var r []Custodian
	for _, el := range info {
		switch el.(type) {
		case []Custodian:
			r = el.([]Custodian)
			return r
		case *Custodians:
			r1 := el.(*Custodians)
			return r1.Data
		}
	}
	return nil
}

// retrieve Secret Sharing config data structure
func retrieveSSharing(info []interface{}) secret.SecretSharer {
	var r secret.SecretSharer
	for _, el := range info {
		switch el.(type) {
		case *secret.Shamir:
			r = el.(*secret.Shamir)
			return r
		}
	}
	return nil
}

// Retreive wallet config
func retrieveWallet(info []interface{}) *WalletConfig {
	var r *WalletConfig
	for _, el := range info {
		switch el.(type) {
		case *WalletConfig:
			r = el.(*WalletConfig)
			return r
		}
	}
	return nil
}

// retreive PrivateKey
func retrievePrivateKeys(info []interface{}) *PrivateKeys {
	for _, el := range info {
		switch el.(type) {
		case *PrivateKeys:
			var r *PrivateKeys
			r = el.(*PrivateKeys)
			return r

		}
	}
	return nil
}

// retreive Storage
func retrieveStorage(info []interface{}) []db.KV {
	for _, el := range info {
		switch el.(type) {
		case []db.KV:
			var r []db.KV
			r = el.([]db.KV)
			return r

		}
	}
	return nil
}

// Retrieve shares data structure
func retrieveShares(info []interface{}) []secret.Share {
	r := make([]secret.Share, 0)
	for _, el := range info {
		switch el.(type) {
		case []secret.Share:
			r = el.([]secret.Share)
			return r
		case secret.Share:
			r = append(r, el.(secret.Share))
			return r
		}
	}
	return nil
}
