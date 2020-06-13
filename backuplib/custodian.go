/*
 Simplified custodian version. Holds nickname and number of keys stored. We keep a copy
 of Custodian in backup so that we remember to whom we distributed key shares and can reclaim
 them later on.
*/

package backuplib

import (
	"bytes"
	"errors"
	"github.com/iden3/go-backup/shamir"
	qrdec "github.com/liyue201/goqr"
	qrgen "github.com/skip2/go-qrcode"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io/ioutil"
	"os"
	"path/filepath"
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
	NShares  int // number of shares provided
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
func addCustodian(nickname, folder string, method int, shares []shamir.Share, startIdx, nshares int) error {
	// add info to custodian
	newCustodian := Custodian{
		Nickname: nickname,
		NShares:  nshares,
	}

	// encode share information to stream of bytes.
	sharesArray := make([]shamir.Share, 0)
	sharesArray = append(sharesArray, shares[startIdx:startIdx+nshares]...)

	// generate QR
	if method == QR {
		shareString := encodeShareToString(sharesArray, folder)
		qrfile := folder + "qr-" + nickname + ".png"
		newCustodian.Fname = qrfile
		err := qrgen.WriteFile(shareString, qrgen.High, 256, qrfile)
		if err == nil {
			custodians := GetCustodians()
			custodians.Data = append(custodians.Data, newCustodian)
			SetCustodians(custodians)
		}
		return err

		// generate Raw data
	} else if method == NONE {
		shareBytes := encodeShareToByte(sharesArray, folder)
		fname := folder + "byte-" + nickname + ".dat"
		newCustodian.Fname = fname
		file, _ := os.Create(fname)
		file.Write(shareBytes)
		file.Close()
		custodians := GetCustodians()
		custodians.Data = append(SecretCustodians.Data, newCustodian)
		SetCustodians(custodians)
		return nil

	} else {
		return errors.New("Invalid Method to distriburt Shares")
	}
}

func initCustodians() {
	var custodians Custodians
	custodiansData := make([]Custodian, 0)
	custodians.Data = custodiansData
	SetCustodians(&custodians)
}

func AddCustodian(nickname, folder string, method int, startIdx, nshares int) error {
	sharesGo := toShares(GetShares())

	err := addCustodian(nickname, folder, method, sharesGo, startIdx, nshares)
	return err
}

func ScanQRShare(fname string) {
	rxSharesGo := scanQRShare(fname)
	rxShareMobile := Shares{Data: fromShares(rxSharesGo)}

	shares := GetShares()
	shares.Data = append(shares.Data, rxShareMobile.Data...)
	SetShares(shares)
}

// Decode QR that includes a share, and return it a slice of maps with the index and the share
func scanQRShare(fname string) []shamir.Share {
	var tmpFname string
	if filepath.Ext(fname) == ".png" {
		dirName := filepath.Dir(fname)
		tmpFname = dirName + "/tmp_f"
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
		file, err := os.Create(tmpFname)
		defer os.Remove(tmpFname)
		if err != nil {
			panic(err)
		}
		file.Write(qrCodes[0].Payload)
		file.Close()

	} else {
		tmpFname = fname
	}

	// tmpFname is a file including the encoded share.
	qrinfo := decode(tmpFname, nil)
	share := retrieveShares(qrinfo)

	return share
}
