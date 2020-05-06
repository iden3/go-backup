/* Aux functions to initialize claim, mk, zkp wallet config data.
*  It also includes very simplified functionality from other modules that should be part of backup package
     but are still not implemented, like custodians, ....

*/

package wrapper

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"encoding/gob"
	"errors"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"

	"github.com/iden3/go-backup/ff"
	fc "github.com/iden3/go-backup/filecrypt"
	"github.com/iden3/go-backup/secret"
	qrdec "github.com/liyue201/goqr"
	qrgen "github.com/skip2/go-qrcode"
)

// Configuration constants
const (
	N_ELEMENTS     = 1000
	ID_LEN         = 31
	MIN_N_SHARES   = 4
	MAX_N_SHARES   = 10
	PRIME          = ff.FF_BN256_PRIME
	BACKUP_DIR     = "./testdata/"
	BACKUP_FILE    = "backup.bk"
	QR_DIR         = "./testdata/"
	PBKDF2_NITER   = 60000
	PBKDF2_SALTLEN = 12
)

var wallet *WalletConfig

// Auxiliary information emulating Wallet Config
// Struxture and contents are not important. Just deinfing some arbitrary data structures
// to do backup
type WalletConfig struct {
	Config map[string][]byte
}

// Dummy data init functions
func initClaims() *Claim {
	var test_data Claim
	for i := 0; i < N_ELEMENTS; i++ {
		test_data.Data[i] = uint64(rand.Intn(1234567)) //1234567123453
	}
	return &test_data
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func initWalletConfig() *WalletConfig {
	var data WalletConfig
	data.Config = make(map[string][]byte)
	for i := 0; i < N_ELEMENTS; i++ {
		st := randStringBytes(13)
		data.Config[st], _ = genRandomBytes((i % 14) + 1)
	}
	return &data
}

func initZKP() *ZKP {
	var zkp ZKP
	zkp.R = initClaims()
	zkp.L = initWalletConfig()

	return &zkp
}

func initMerkleTree() *MT {
	var mt MT
	for i := 0; i < N_ELEMENTS; i++ {
		mt.Y[i] = initClaims()
	}

	return &mt
}

///// Secret Sharing Wrapper
// Utility functions to convert between types.
// secret sharing package needs to be improved to
// support more convenient data types and avoid so much conversion

var secret_cfg secret.Shamir

// Generate shares from secret
func GenerateShares(secret []byte) []secret.Share {
	// convert secret to right format
	secret_ff, _ := ff.NewElement(PRIME)
	secret_ff.FromByte(secret)
	new_shares, _ := secret_cfg.GenerateShares(secret_ff)

	return new_shares

}

// Generate secret from shares
func GenerateKey(shares []secret.Share, sharing_cfg secret.SecretSharer) []byte {
	shares_pool := make([]secret.Share, 0)
	for _, share := range shares {
		shares_pool = append(shares_pool, share)
		if len(shares_pool) == sharing_cfg.GetMinShares() {
			break
		}
	}
	secret, err := sharing_cfg.GenerateSecret(shares_pool)
	if err != nil {
		panic(err)
	}

	return secret.ToByte()
}

//////
// Custodian

// Simplified custodian version. Holds nickname and number of keys stored. We keep a copy
// of Custodian in backup so that we remember to whom we distributed key shares and can reclaim
// them later on.

// Attempts to emulate how we could exchage shares. QR and NONE  the only one working in this demo
const (
	EMAIL = iota
	PHONE
	TELEGRAM
	QR   // Generate QR
	NONE // send raw data directly
)

type Custodian struct {
	Nickname string
	N_shares int // number of shares provided
	Fname    string
}

var custodians []Custodian

// Add new Custodian and simulate the distribution of N shares
func AddCustodian(nickname string, method int, shares []secret.Share, start_idx, nshares int) error {
	// add info to custodian
	new_custodian := Custodian{
		Nickname: nickname,
		N_shares: nshares,
	}

	// encode share information to stream of bytes.
	shares_array := make([]secret.Share, 0)
	shares_array = append(shares_array, shares[start_idx:start_idx+nshares]...)

	// generate QR
	if method == QR {
		share_string := encodeShareToString(shares_array)
		qrfile := QR_DIR + "qr-" + nickname + ".png"
		new_custodian.Fname = qrfile
		err := qrgen.WriteFile(share_string, qrgen.High, 256, qrfile)
		if err == nil {
			custodians = append(custodians, new_custodian)
		}
		return err

		// generate Raw data
	} else if method == NONE {
		share_bytes := encodeShareToByte(shares_array)
		fname := QR_DIR + "byte-" + nickname + ".dat"
		new_custodian.Fname = fname
		file, _ := os.Create(fname)
		file.Write(share_bytes)
		file.Close()
		custodians = append(custodians, new_custodian)
		return nil

	} else {
		return errors.New("Invalid Method to distriburt Shares")
	}
}

// Decode QR that includes a share, and return it a slice of maps with the index and the share
func ScanQRShare(cust *Custodian) []secret.Share {
	var tmp_fname string
	if filepath.Ext(cust.Fname) == ".png" {
		tmp_fname = QR_DIR + "tmp_f"
		imgdata, err := ioutil.ReadFile(cust.Fname)
		if err != nil {
			panic(err)
		}

		img, _, err := image.Decode(bytes.NewReader(imgdata))
		if err != nil {
			panic(err)
		}
		qrCodes, err := qrdec.Recognize(img)
		if err != nil {
			panic(err)
		}
		file, err := os.Create(tmp_fname)
		if err != nil {
			panic(err)
		}
		file.Write(qrCodes[0].Payload)
		file.Close()

	} else {
		tmp_fname = cust.Fname
	}

	// tmp_fname is a file including the encoded share.
	qrinfo := Decode(tmp_fname, nil)

	share := RetrieveShares(qrinfo)
	return share
}

///// Encoding Layer

// Types of data we can include in the backup. Needed to register the data strcuture
const (
	CLAIMS = iota
	WALLET_CONFIG
	ZKP_INFO
	MERKLE_TREE
	CUSTODIAN
	GENID
	SSHARING
	SHARES
	// Add other possible data types that we need encoding
)

// Register data strucrure
func encodeType(dtype int) {
	switch dtype {
	case CLAIMS:
		gob.Register(&Claim{})

	case WALLET_CONFIG:
		gob.Register(&WalletConfig{})

	case ZKP_INFO:
		gob.Register(&ZKP{})

	case MERKLE_TREE:
		gob.Register(&MT{})

	case CUSTODIAN:
		gob.Register(&Custodian{})
		var el []Custodian
		gob.Register(el)

	case GENID:
		var el []byte
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
	}
}

// Transform share encoding to string
func encodeShareToString(shares []secret.Share) string {
	tmp_fname := QR_DIR + "share-tmp.dat"
	encodeShare(shares)
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
func encodeShareToByte(shares []secret.Share) []byte {
	tmp_fname := QR_DIR + "share-tmp.dat"
	encodeShare(shares)
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
func encodeShare(shares []secret.Share) {
	encodeType(SHARES)

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
	tmp_fname := QR_DIR + "share-tmp.dat"

	err = fc.Encrypt(hdr_k, hdr_e, tmp_fname, shares)
	if err != nil {
		panic(err)
	}
}

// Decode and decrypt file using provided key
func Decode(fname string, key []byte) []interface{} {
	results, _ := fc.Decrypt(fname, key)
	return results
}

// Retrieve functions return a specific data type from a generic type

// retrieve Custodian data structure
func RetrieveCustodians(info []interface{}) []Custodian {
	var r []Custodian
	for _, el := range info {
		switch el.(type) {
		case []Custodian:
			r = el.([]Custodian)
			return r
		}
	}
	return nil
}

// retrieve Secret Sharing config data structure
func RetrieveSSharing(info []interface{}) secret.SecretSharer {
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

// Retrieve Genesis ID
func RetrieveID(info []interface{}) []byte {
	var r []byte
	for _, el := range info {
		switch el.(type) {
		case []byte:
			r = el.([]byte)
			return r
		}
	}
	return nil

}

// Retrieve Claim data structure
func RetrieveClaims(info []interface{}) *Claim {
	var r *Claim
	for _, el := range info {
		switch el.(type) {
		case *Claim:
			r = el.(*Claim)
			return r
		}
	}
	return nil
}

// Retreive wallet config
func RetrieveWallet(info []interface{}) *WalletConfig {
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

// retreive ZKP data
func RetrieveZKP(info []interface{}) *ZKP {
	var r *ZKP
	for _, el := range info {
		switch el.(type) {
		case *ZKP:
			r = el.(*ZKP)
			return r
		}
	}
	return nil
}

// Retrieve MT data structure
func RetrieveMT(info []interface{}) *MT {
	var r *MT
	for _, el := range info {
		switch el.(type) {
		case *MT:
			r = el.(*MT)
			return r
		}
	}
	return nil
}

// Retrieve shares data structure
func RetrieveShares(info []interface{}) []secret.Share {
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

// Backup layer
/////  Backup Layer

const (
	ENCRYPT = iota
	DONT_ENCRYPT
)

type Backup struct {
	data interface{}
	mode int
}

// Summary of contents of backup file
var backup_registry map[int]Backup

// Record and register backup data structures
func AddToBackup(t int, d interface{}, action int) {
	// check for duplicates
	for idx, _ := range backup_registry {
		if idx == t {
			return
		}
	}
	// encode type
	encodeType(t)

	// Add to backup registry
	backup_el := Backup{data: d,
		mode: action,
	}
	backup_registry[t] = backup_el
}

// Generate backup file
func CreateBackup(key_t, hash_t, enc_t int, fname string, key []byte) {
	// Add Key -> for now, only PBKDF2 + GCM supported, but it can be expanded easily
	//  Assume fixed PBKDF2 config. Header shared for both encrypted and non encrpyted blocks
	hdr_k := &fc.Pbkdf2Fc{}
	err := hdr_k.FillHdr(fc.FC_HDR_VERSION_1, key_t, hash_t,
		PBKDF2_NITER, fc.FC_BSIZE_BYTES_256, PBKDF2_SALTLEN, key)
	if err != nil {
		panic(err)
	}

	n_blocks := len(backup_registry)
	var block_idx, bctr = 0, 0

	// There are two types of blcks defined for now:
	// Encrypted -> PBKDF2 Key Header + GCM Enc Header
	// Not Encrypted -> PBKDF2 Key HEader + ClearFC Enc Header
	for _, el := range backup_registry {
		// Check block index
		if n_blocks == 1 {
			block_idx = fc.FC_HDR_BIDX_SINGLE
		} else if n_blocks == bctr+1 {
			block_idx = fc.FC_HDR_BIDX_LAST
		} else if bctr == 0 {
			block_idx = fc.FC_HDR_BIDX_FIRST
		} else {
			block_idx = fc.FC_HDR_BIDX_MID
		}

		// Add Enc Header
		if el.mode == DONT_ENCRYPT {
			hdr_ne := &fc.ClearFc{}
			err = hdr_ne.FillHdr(fc.FC_HDR_VERSION_1, fc.FC_CLEAR, fc.FC_BSIZE_BYTES_256, block_idx)
			err = fc.Encrypt(hdr_k, hdr_ne, BACKUP_DIR+BACKUP_FILE, el.data)
		} else if el.mode == ENCRYPT {
			hdr_gcm := &fc.GcmFc{}
			err = hdr_gcm.FillHdr(fc.FC_HDR_VERSION_1, fc.FC_GCM, fc.FC_BSIZE_BYTES_256, block_idx)
			err = fc.Encrypt(hdr_k, hdr_gcm, BACKUP_DIR+BACKUP_FILE, el.data)
		}
		if err != nil {
			panic(err)
		}
		bctr += 1
	}
}

/////  Aux
// Generate N random bytes.
func genRandomBytes(noncesize int) ([]byte, error) {
	nonce := make([]byte, noncesize)
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

////
func init() {
	//init aux data
	claims = initClaims()
	wallet = initWalletConfig()
	zKPData = initZKP()
	merkleTree = initMerkleTree()

	// init Secret Sharing
	err := secret_cfg.NewConfig(MIN_N_SHARES, MAX_N_SHARES, PRIME)
	if err != nil {
		panic(err)
	}
	backup_registry = make(map[int]Backup)

}

func CheckEqual(expected, obtained interface{}) bool {
	flag := false

	switch obtained.(type) {
	case []map[uint64]ff.Element:
		o := obtained.([]map[uint64]ff.Element)
		flag = reflect.DeepEqual(expected, o[0])

	default:
		flag = reflect.DeepEqual(expected, obtained)
	}
	return flag
}
