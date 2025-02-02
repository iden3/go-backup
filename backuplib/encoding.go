///// Encoding Layer

package backuplib

import (
	"bufio"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/iden3/go-backup/ff"
	fc "github.com/iden3/go-backup/filecrypt"
	"github.com/iden3/go-backup/shamir"
	"github.com/iden3/go-iden3-core/db"
	"github.com/iden3/go-iden3-crypto/babyjub"
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
		gob.Register(&shamir.Shamir{})

	case SHARES:
		el1, _ := ff.NewElement(PRIME)
		var el2 shamir.Share
		var el3 []shamir.Share
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

// Transform share encoding to []byte
func encodeShareToByte(shares []shamir.Share, folder string) []byte {
	tmpFname := folder + "share-tmp.dat"
	encodeShare(shares, tmpFname)
	defer os.Remove(tmpFname)
	data := readBinaryFile(tmpFname)

	return data
}

// Read file
func readBinaryFile(tmpFname string) []byte {
	file, err := os.Open(tmpFname)
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
func encodeShare(shares []shamir.Share, fname string) error {
	// Key header -> no key (only for hmac)
	//key := []byte("ThisIsMySecretKey")
	fileCrypt, err := fc.New(1, fname, nil, nil, fc.FC_KEY_T_NOKEY)
	if err != nil {
		return fmt.Errorf("New FC : %w", err)
	}
	// Encryption header -> not encrypted
	err = fileCrypt.AddBlock([]byte("SHARES"), fc.FC_CLEAR, shares)
	if err != nil {
		return fmt.Errorf("Add Block : %w", err)
	}
	return nil
}

// Decode and decrypt file using provided key
func DecodeUnencrypted(fname string) error {
	//key := []byte("ThisIsMySecretKey")
	info := decode(fname, nil)

	rxCustodians := retrieveCustodians(info)

	if rxCustodians == nil {
		return errors.New("Invalid Custodian Format")
	} else {
		initCustodians()
		custodians := GetCustodians()
		custodians.Data = rxCustodians
		SetCustodians(custodians)
	}

	rxSecretCfg := retrieveSSharing(info)

	if rxSecretCfg == nil {
		return errors.New("Invalid Secret Sharing Format")
	} else {
		initSecretCfg()
		secretCfg := GetSecretCfg()
		secretCfg.MinShares = rxSecretCfg.GetMinShares()
		secretCfg.MaxShares = rxSecretCfg.GetMaxShares()
		secretCfg.ElementType = rxSecretCfg.GetElType()
		SetSecretCfg(secretCfg)
	}

	return nil
}

func DecodeEncrypted(fname string) error {
	key := GetkOp()
	info := decode(fname, key)

	retrievedWallet := retrieveWallet(info)
	if retrievedWallet == nil {
		return errors.New("Invalid Wallet Format")
	} else {
		SetWallet(retrievedWallet)
	}

	retrievedShares := retrieveShares(info)
	if retrievedShares == nil {
		return errors.New("Invalid shares Format")
	} else {
		shares := GetShares()
		shares.Data = fromShares(retrievedShares)
		SetShares(shares)
	}

	retrievedPrivateKeys := retrievePrivateKeys(info)
	if retrievedPrivateKeys == nil {
		return errors.New("Invalid Private Keys Format")
	} else {
		SetPrivateKeys(retrievedPrivateKeys)
	}

	retrievedStorage := retrieveStorage(info)
	if retrievedStorage == nil {
		return errors.New("Invalid Storage Format")
	} else {
		SetStorage(retrievedStorage)
	}

	return nil

}

// Decode and decrypt file using provided key
func decode(fname string, key []byte) []interface{} {
	newFC, _ := fc.NewFromFile(key, fname)
	results, _ := newFC.DecryptAll(key)

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
func retrieveSSharing(info []interface{}) *shamir.Shamir {
	var r *shamir.Shamir
	for _, el := range info {
		switch el.(type) {
		case *shamir.Shamir:
			r = el.(*shamir.Shamir)
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
func retrieveShares(info []interface{}) []shamir.Share {
	r := make([]shamir.Share, 0)
	for _, el := range info {
		switch el.(type) {
		case []shamir.Share:
			r = el.([]shamir.Share)
			return r
		case shamir.Share:
			r = append(r, el.(shamir.Share))
			return r
		}
	}
	return nil
}
