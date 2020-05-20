/*
  Identity wrapper
*/

package backuplib

import (
	"github.com/iden3/go-iden3-core/db"
	"github.com/iden3/go-iden3-core/keystore"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/iden3-mobile/go/iden3mobile"
	"io/ioutil"
	"os"
)

var id *iden3mobile.Identity

type PrivateKeys struct {
	PK []babyjub.PrivateKey
}

// Init
func initIdentity(pass []byte, folder string) error {
	c = config{
		Web3Url:            WEB3URL,
		HolderTicketPeriod: HOLDER_TICKET_PERIOD,
	}

	if pass == nil {
		id = nil
		return nil
	}
	// New identity without extra claims
	dir1, err := ioutil.TempDir(folder, IDENTITY_MAIN_STORAGE)
	if err != nil {
		return err
	}
	rmDirs = append(rmDirs, dir1)
	_id, err := iden3mobile.NewIdentity(dir1, string(pass), c.Web3Url, c.HolderTicketPeriod, iden3mobile.NewBytesArray(), nil)
	if err != nil {
		return err
	}
	id = _id
	return nil
}

// KeyStore to Private Keys
func keyStore2PK(ks *keystore.KeyStore, pass []byte) error {
	keys := ks.Keys()
	backupPK := make([]babyjub.PrivateKey, 0)
	for _, key := range keys {
		pk, err := ks.ExportKey(&key, pass)
		if err != nil {
			return nil
		}
		backupPK = append(backupPK, *pk)
	}
	PK := PrivateKeys{PK: backupPK}
	dataBackup.pK = &PK
	return nil
}

// db.Storage to KV
func storage2KV(sto db.Storage) error {
	r := []db.KV{}
	lister := func(k []byte, v []byte) (bool, error) {
		r = append(r, db.KV{clone(k), clone(v)})
		return true, nil
	}

	err := sto.Iterate(lister)
	dataBackup.storage = r

	return err
}

func restoreStorage(folder string) (db.Storage, error) {
	// Create empty storage
	storage_folder := folder + "/" + FOLDER_STORE
	err := os.Mkdir(storage_folder, 0777)
	if err != nil {
		return nil, err
	}
	sto, err := db.NewLevelDbStorage(storage_folder+STORE_FILE, false)
	if err != nil {
		return nil, err
	}

	// Fill storage with backup contents
	//    Prepare new Tx
	tx, err := sto.NewTx()
	if err != nil {
		return nil, err
	}
	//   Retrieve copy of storage backup
	backup_storage := GetStorage()
	//   Iterate through backup KV values and insert them to new storage
	for _, kv := range backup_storage {
		tx.Put(kv.K, kv.V)
	}

	return sto, nil
}

func restoreKStore(folder string, params keystore.KeyStoreParams) (*keystore.KeyStore, error) {
	// Create empty storage
	kstorage_folder := folder + "/" + FOLDER_KSTORE
	err := os.Mkdir(kstorage_folder, 0777)
	if err != nil {
		return nil, err
	}
	storage := keystore.NewFileStorage(kstorage_folder + KSTORE_FILE)
	ks, err := keystore.NewKeyStore(storage, params)
	if err != nil {
		return nil, err
	}

	// Restore backup copy
	backup_kstore := GetPrivateKeys()
	pass := GetkOp()
	for _, pk := range backup_kstore.PK {
		_, err = ks.ImportKey(pk, pass)
		if err != nil {
			return nil, err
		}
	}

	return ks, err
}

func RestoreIdentity(folder string, params keystore.KeyStoreParams) (*iden3mobile.Identity, error) {
	dir, err := ioutil.TempDir(folder, IDENTITY_MAIN_STORAGE)
	// Restore Storage
	_, err = restoreStorage(dir)
	if err != nil {
		return nil, err
	}

	// Restore Key Store
	_, err = restoreKStore(dir, params)
	if err != nil {
		return nil, err
	}

	pass := GetkOp()
	rmDirs = append(rmDirs, dir)
	_id, err := iden3mobile.NewIdentityLoad(dir, string(pass), c.Web3Url, c.HolderTicketPeriod, nil)
	if err != nil {
		return nil, err
	}

	return _id, nil
}
