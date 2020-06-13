package backuplib

import (
	"fmt"
	fc "github.com/iden3/go-backup/filecrypt"
	"github.com/iden3/go-iden3-core/db"
	"github.com/iden3/go-iden3-core/keystore"
	"os"
	"testing"
)

var oldKOp []byte
var oldWallet WalletConfig
var oldShares Shares
var oldSecretCfg Secret
var oldCustodians Custodians
var oldPK PrivateKeys
var oldStorage []db.KV

func copyBackupData() {
	oldKOp = GetkOp()
	oldWallet = *GetWallet()
	oldShares = *GetShares()
	oldSecretCfg = *GetSecretCfg()
	oldCustodians = *GetCustodians()
	oldPK = *GetPrivateKeys()
	oldStorage = GetStorage()
}

func deleteBackupData() {
	SetkOp(nil)
	SetWallet(nil)
	SetShares(nil)
	SetSecretCfg(nil)
	SetCustodians(nil)
	SetPrivateKeys(nil)
	SetStorage(nil)

}

func TestBackup(t *testing.T) {
	// Generates Key. This is our Identity operational Key. I am assuming
	// that the operational key is the one that enables us to regain the identity.
	kOp := KeyOperational()
	SetkOp(kOp)

	// Create identity and initialize modules
	Init(kOp, "")

	// Generate Shares of our operational Key
	GenerateShares(kOp)

	// Define Custodians -> Simulates the process of inviting a trusted entity to
	//   become our custodian, and sending N shares of the key upon acceptance of the invitation. In this example
	//   we generate a QR, but we could encrypt the share information and send it via some
	//   alternative mechanism (EMAIL, TELEGRAM, P2P connection).
	//
	//   During the process of adding a custodian, we also could link this custodian with
	//   the contact details of this person available in the agenda so that we know
	//   how to contact them in the future.

	// assign first share
	AddCustodian("Pedrito", QR_DIR, QR, 0, 1)
	// assign second share
	AddCustodian("Faustino", QR_DIR, QR, 1, 1)
	// assign third and fourth share
	AddCustodian("Sara Baras", QR_DIR, QR, 2, 2)
	// assign 5th share
	AddCustodian("Sergio", QR_DIR, QR, 4, 1)
	// assign 6th share
	AddCustodian("Raul", QR_DIR, QR, 5, 1)

	// Define which information is included in Backup file. Contents of the backup are not important right
	// now. It is just to show how easy it is to build the backup file.
	// At this point, the buildup is static (I need to have a switch case in AddToBackup with all possible
	// data stucture types that can be added to the backup, but there should be a more dynamic way...)
	// Add wallet configuration
	AddToBackup(WALLET_CONFIG, ENCRYPT)
	// Add Custodian information (contact details) -> unencrypted
	AddToBackup(CUSTODIAN, DONT_ENCRYPT)
	// Add SSharing info. We need Prime number and protocol used (Shamir) -> unencrypted
	AddToBackup(SSHARING, DONT_ENCRYPT)
	// Add Shares. We heed to keep a list of at least outstanding shares in case
	//  we want to redistribute in the future. in this example I keep all for simplicity.
	AddToBackup(SHARES, ENCRYPT)
	// Add KeyStore
	AddToBackup(PKEYS, ENCRYPT)
	// Add Storage
	AddToBackup(STORAGE, ENCRYPT)

	// Generate Backupfile -> Here we select the Key derivation algo and the encryption mechanism used
	//  for encrypted sections. Also not, that we can mix encrypted and non-encrpyted information in the
	// same baclup file
	err := CreateBackup(fc.FC_KEY_T_PBKDF2, fc.FC_HASH_SHA256, fc.FC_GCM, BACKUP_FILE)
	if err != nil {
		t.Error(err)
	}

	// We lost our phone.  We need to reinstall wallet in new phone and retrieve backup
	// from cloud services. Copy old data to check backup is done correctly and delete
	copyBackupData()
	deleteBackupData()
}

func TestRestore(t *testing.T) {
	Init(nil, "")

	// Decode unencrypted backup file as it may contain some info
	// (custodian contact info, genesis id, sharing)

	// During this fist stage, we only recover nonencrypted data as we still don't have the key.
	err := DecodeUnencrypted(BACKUP_FILE)
	if err != nil {
		t.Error(err)
	}

	res := checkEqual(oldCustodians, *GetCustodians())
	if res {
		fmt.Println("Retrieved Custodians .... OK")
	} else {
		t.Error("Retrieved Custodians .... KO")
	}

	// Retreive sharing info -> Finite Field information and protocol (Shamir's secret sharing) required to
	//    regenerate the KEY. It is unencrypted
	res = checkEqual(oldSecretCfg, *GetSecretCfg())
	if res {
		fmt.Println("Retrieved Sharing Conf .... OK")
	} else {
		fmt.Println(oldSecretCfg, *GetSecretCfg())
		t.Error("Retrieved Sharing Conf .... KO")
	}

	// Contact custodians and retrieve shares
	// We simulate here that somehow we contact the custodians using the info in the backup
	//    Out of the 5 custodians we had, we ony contacted   three.
	// The custodian then sends the share in P2P channel. In our case, we assume that we are
	//  face to face and the custodian gfenerates a QR that we can scan.
	custodians := GetCustodians()
	for _, custodian := range custodians.Data {
		ScanQRShare(custodian.Fname)
	}

	// Generate Key
	//   Using the collected shares, regenerate Key
	kOp := GenerateKey()
	SetkOp(kOp)
	res = checkEqual(oldKOp, GetkOp())
	if res {
		fmt.Println("Retrieved kOp .... OK")
	} else {
		t.Error("Retrieved kOp .... KO")
	}

	// Decode and Decrypt backup file -> With the generated kOp, try to decrypt file.
	//   kOp is not used directly. We use a Key Derivation Function. All parameters for this
	//   function are public (except for the Key) and are in the encryption block header
	DecodeEncrypted(BACKUP_FILE)

	// With the decrpyted and decoded information, retrieve all information we stored and check
	// if it is equal than the original
	res = checkEqual(oldWallet, *GetWallet())
	if res {
		fmt.Println("Retrieved Wallet .... OK")
	} else {
		t.Error("Retrieved Wallet .... KO")
	}

	res = checkEqual(oldShares, *GetShares())
	if res {
		fmt.Println("Retrieved Shares .... OK")
	} else {
		t.Error("Retrieved Shares .... KO")
	}

	res = checkEqual(oldPK, *GetPrivateKeys())
	if res {
		fmt.Println("Retrieved Private Keys .... OK")
	} else {
		t.Error("Retrieved Private Keys .... KO")
	}

	res = checkEqual(oldStorage, GetStorage())
	if res {
		fmt.Println("Retrieved Storage .... OK")
	} else {
		t.Error("Retrieved Storage .... KO")
	}

	// Last step is to restore identity
	_, err = RestoreIdentity("", keystore.StandardKeyStoreParams)
	if err != nil {
		t.Error(err)
	}

	for _, dir := range rmDirs {
		os.RemoveAll(dir)
	}

}
