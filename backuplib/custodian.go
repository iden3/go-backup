/*
 Simplified custodian version. Holds nickname and number of keys stored. We keep a copy
 of Custodian in backup so that we remember to whom we distributed key shares and can reclaim
 them later on.
*/

package backuplib

import (
	"bytes"
	"errors"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io/ioutil"
	"os"
	"path/filepath"
	"github.com/iden3/go-backup/secret"
	qrdec "github.com/liyue201/goqr"
	qrgen "github.com/skip2/go-qrcode"
)
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

type Custodians struct {
      Data []Custodian
}

var SecretCustodians *Custodians

func GetNCustodians() int {
   custodians := GetCustodians()
   return len(custodians.Data)
}

func GetCustodian(n int) *Custodian {
   custodians := GetCustodians()
   if n < len(custodians.Data) {
      return &custodians.Data[n]
   } else {
     return nil
   }
}

// Add new Custodian and simulate the distribution of N shares
func addCustodian(nickname, folder string, method int, shares []secret.Share, start_idx, nshares int) error {
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
		share_string := encodeShareToString(shares_array, folder)
		qrfile := folder + "qr-" + nickname + ".png"
		new_custodian.Fname = qrfile
		err := qrgen.WriteFile(share_string, qrgen.High, 256, qrfile)
		if err == nil {
                        custodians := GetCustodians()
			custodians.Data = append(custodians.Data, new_custodian)
                        SetCustodians(custodians)
		}
		return err

		// generate Raw data
	} else if method == NONE {
		share_bytes := encodeShareToByte(shares_array, folder)
		fname := folder + "byte-" + nickname + ".dat"
		new_custodian.Fname = fname
		file, _ := os.Create(fname)
		file.Write(share_bytes)
		file.Close()
                custodians := GetCustodians()
		custodians.Data = append(SecretCustodians.Data, new_custodian)
                SetCustodians(custodians)
		return nil

	} else {
		return errors.New("Invalid Method to distriburt Shares")
	}
}

func InitCustodians() {
  var custodians Custodians
  custodians_data := make([]Custodian,0)
  custodians.Data = custodians_data
  SetCustodians(&custodians)

}

func AddCustodian(nickname, folder string, method int, start_idx, nshares int) error {
  shares_go := toShares(GetShares())
  
  err := addCustodian(nickname, folder, method, shares_go, start_idx, nshares)
  return err
}

func ScanQRShare(fname string) {
   rx_shares_go := scanQRShare(fname)
   rx_share_mobile := Shares{Data : fromShares(rx_shares_go)}

   shares := GetShares()
   shares.Data = append(shares.Data, rx_share_mobile.Data...)
   SetShares(shares)
}

// Decode QR that includes a share, and return it a slice of maps with the index and the share
func scanQRShare(fname string) []secret.Share {
	var tmp_fname string
	if filepath.Ext(fname) == ".png" {
                dir_name  := filepath.Dir(fname)
		tmp_fname = dir_name+"/tmp_f"
		imgdata, err := ioutil.ReadFile(fname)
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
	        defer os.Remove(tmp_fname)
		if err != nil {
			panic(err)
		}
		file.Write(qrCodes[0].Payload)
		file.Close()

	} else {
		tmp_fname = fname
	}

	// tmp_fname is a file including the encoded share.
	qrinfo := decode(tmp_fname, nil)
	share := retrieveShares(qrinfo)

	return share
}

