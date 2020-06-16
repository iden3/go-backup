
# Filecrypt
Package filecrypt implements filecrypt encryption and decryption protocol

Filecrypt procotol is used to encrypt a set of different data structures
into a file. It adds enough information in a header to be able to decrypt it 
at a later time.

A filecrypt object includes a  Digest Header, Key Header, a Encryption header, and a sequence of payload blocks. There may be multiple filecrypt blocks with different encryption options. Typically, a filecrypt block includes a single data structure. Multiple filecrypt blocks can be appended toguether to encrypt several data structures with different Encryption Headers.

All headers  are always unencrypted. 
Payload blocks may or may not be encryted.

**NOTE** Before using filecrypt, you should call *gob.Register()* function to register the data strcutre you want to backup

Filecrypt currently supports two encryption schemes:
- GCM : Symmetric Encryption
- RSA : Asymmetric Encryption

## Digest Header Format

|Field | Length | Description |
|------|--------|-------------|
| **Version** | 1 Byte | Version 0 |
| **nBlocks** | 8 Bytes | Number of FileCrypt blocks |

For every block:

|Field | Length | Description |
|------|--------|-------------|
| **Offset**| 8 Bytes | Startig location of FileCrypt block (in bytes)|
| **Tag**   | 9 Bytes | Tag to query the block during decryption. First byte includes tag size in bytes|


## Key Header Format
It includes information to generate a key from a master key


|Field | Length | Description|
|------|--------|------------|
| **Version** | 1 Byte | Version 0 |
| **Key Type** |   1 Byte | Different key types : no key (*FC_KEY_T_NOKEY*), direct key (*FC_KEY_T_DIRECT*) or PBKDF2 (*FC_KEY_T_PBKDF2*)|
| **VAR** |Variable size| variable fields|

There is only a single key header per file. All blocks use same key derivation mechanism:
- No Key : Payload Not encrypted
- Direct Key :  Key is used as is to encrypt payload
- PBKDF2 : Uses PBKDF2 as Key Derivation function

If mechanism selected is PBKDF2, vAR fields include:

|Field | Length | Description |
|------|--------|-------------|
| **Length** | 1 Byte | Variable field length |
| **Hash** | 1 Byte | Hash function used |
| **Iter** | 4 Byte | Number of iterations|
| **KeyLen** | 1 Byte | Resulting key length in bytes |
| **SaltLen** | 1 Byte | Salt Length |

Currently No Hash (*FC_NOHASH*) or SHA256 (*FC_HASH_SHA256*) are implemented as hash functions



## Encryption Header Format
Encryption Header is 16 bytes long. Contents include

|Field | Length | Description |
|------|--------|-------------|
| **Version** | 1 Byte | Version 0 |
| **FC type** |1 byte| encryption type.  Not encrypted (*FC_CLEAR*), GCM (*FC_GCM*) , RSA (*FC_RSA*) |
| **Blocksize**  |1 byte | Encryption block size. Currently 128 (*FC_BSIZE_BYTES_128*) and 256 (*FC_BSIZE_BYTES_256*) for GCM or 2048 (*FC_BSIZE_BYTES_2048*) and 4096 (*FC_BSIZE_BYTES_4096*) for RSA |
| **Noncesize**  |1 byte | Size in bytes of nonce. Can be 0 |
| **Last_blocksize** |1 byte | Size in bytes of last cleartext block|
| **Nblocks**      |8 byte| Number of blocks |



## Examples

### GCM with Direct Key

In this example we will encrypt three different blocks with GCM-256
```	

type FCTest struct{
   SecretText string
}

// init tests data
testData1 := initFCTest1(12)
testData2 := initFCTest1(2335)
testData3 := initFCTest1(123232)
testData := []*FCTest1{testData1, testData2, testData3}

// register struct
gob.Register(&FCTest1{})

// init key
key, err := genRandomBytes(FC_BSIZE_BYTES_256)

tags := [3]string{"BLOCK1", "BLOCK2", "BLOCK3"}
fc, err := New(3, "./testdata/sample1.dat", nil, key, FC_KEY_T_DIRECT)
if err != nil {
	fmt.Errorf("Error creating FileCrypt Object")
}

// encrypt first block
err = fc.AddBlock([]byte(tags[0]), FC_GCM, testData1)
if err != nil {
	fmt.Errorf("Error Creating FileCrypt Block") 
}

// encrypt second block
err = fc.AddBlock([]byte(tags[1]), FC_GCM, testData2)
if err != nil {
	fmt.Errorf("Error Creating FileCrypt Block") 
}

// encrypt last block
err = fc.AddBlock([]byte(tags[2]), FC_GCM, testData3)
if err != nil {
	fmt.Errorf("Error Creating FileCrypt Block") 
}

// Decode filecrypt
newFC, err := NewFromFile("./testdata/sample1.dat")
if err != nil {
	fmt.Errorf("Error recovering FileCrypt Header") 
}

newTags := newFC.ListTags()
// Check Tags
for idx := 0; idx < len(tags); idx += 1 {
	if !bytes.Equal(newTags[idx], []byte(tags[idx])) {
               fmt.Errorf("Tags not equal")
	}
}
result, err := newFC.DecryptAll(key)
if err != nil {
	fmt.Errorf("Error Decrypting") 
}
if len(result) != 3 {
	fmt.Errorf("Unexpected result length")
}
r1 := *result[0].(*FCTest1)
r2 := *result[1].(*FCTest1)
r3 := *result[2].(*FCTest1)

if r1 != *testData1 {
	fmt.Errorf("Encrypted and decrypted values not equal")
}
if r2 != *testData2 {
	fmt.Errorf("Encrypted and decrypted values not equal")
}
if r3 != *testData3 {
	fmt.Errorf("Encrypted and decrypted values not equal")
}

for idx := 0; idx < len(tags); idx += 1 {
	result, err := newFC.DecryptSingle([]byte(tags[idx]), key)
	if err != nil {
	      fmt.Errorf("Error Decrypting") 
	}
	r := *result.(*FCTest1)
	if r != *testData[idx] {
	   fmt.Errorf("Encrypted and decrypted values not equal")
	}

}

```

### RSA with Direct Key

In this example we will encrypt three different blocks with GCM-256

```	
type FCTest struct{
   SecretText string
}

// init tests data
testData1 := initFCTest1(12)
testData2 := initFCTest1(2335)
testData3 := initFCTest1(123232)
testData := []*FCTest1{testData1, testData2, testData3}

// register struct
gob.Register(&FCTest1{})

// init key
privKey, _ := rsa.GenerateKey(cr.Reader, FC_BSIZE_BYTES_2048*8)
publicKeyB, _ := json.Marshal(privKey.PublicKey)
privateKeyB, _ := json.Marshal(privKey)

tags := [3]string{"BLOCK1", "BLOCK2", "BLOCK3"}
fc, err := New(3, "./testdata/sample1.dat", nil, publicKeyB, FC_KEY_T_DIRECT)
if err != nil {
	fmt.Errorf("Error creating FileCrypt Object")
}

// encrypt first block
err = fc.AddBlock([]byte(tags[0]), FC_RSA, testData1)
if err != nil {
	fmt.Errorf("Error Creating FileCrypt Block") 
}

// encrypt second block
err = fc.AddBlock([]byte(tags[1]), FC_RSA, testData2)
if err != nil {
	fmt.Errorf("Error Creating FileCrypt Block") 
}

// encrypt last block
err = fc.AddBlock([]byte(tags[2]), FC_RSA, testData3)
if err != nil {
	fmt.Errorf("Error Creating FileCrypt Block") 
}

// Decode filecrypt
newFC, err := NewFromFile("./testdata/sample1.dat")
if err != nil {
	fmt.Errorf("Error recovering FileCrypt Header") 
}

newTags := newFC.ListTags()
// Check Tags
for idx := 0; idx < len(tags); idx += 1 {
	if !bytes.Equal(newTags[idx], []byte(tags[idx])) {
               fmt.Errorf("Tags not equal")
	}
}
result, err := newFC.DecryptAll(privateKeyB)
if err != nil {
	fmt.Errorf("Error Decrypting") 
}
if len(result) != 3 {
	fmt.Errorf("Unexpected result length")
}
r1 := *result[0].(*FCTest1)
r2 := *result[1].(*FCTest1)
r3 := *result[2].(*FCTest1)

if r1 != *testData1 {
	fmt.Errorf("Encrypted and decrypted values not equal")
}
if r2 != *testData2 {
	fmt.Errorf("Encrypted and decrypted values not equal")
}
if r3 != *testData3 {
	fmt.Errorf("Encrypted and decrypted values not equal")
}

for idx := 0; idx < len(tags); idx += 1 {
	result, err := newFC.DecryptSingle([]byte(tags[idx]), privateKeyB)
	if err != nil {
	      fmt.Errorf("Error Decrypting") 
	}
	r := *result.(*FCTest1)
	if r != *testData[idx] {
	   fmt.Errorf("Encrypted and decrypted values not equal")
	}

}

```

### Mixed No encryption and GCM with PBKDF2 
In this example we will encrypt the first and third blocks with GCM-256 using PBKDF2 key derivation function and the second block will be unencrypted.

```

type FCTest struct{
   SecretText string
}

// init tests data
testData1 := initFCTest1(12)
testData2 := initFCTest1(2335)
testData3 := initFCTest1(123232)
testData := []*FCTest1{testData1, testData2, testData3}

// register struct
gob.Register(&FCTest1{})

// init key
key, err := genRandomBytes(FC_BSIZE_BYTES_256)

tags := [3]string{"BLOCK1", "BLOCK2", "BLOCK3"}
fc, err := New(3, "./testdata/sample1.dat", nil, key, FC_KEY_T_PBKDF2)
if err != nil {
	fmt.Errorf("Error creating FileCrypt Object")
}

// encrypt first block
err = fc.AddBlock([]byte(tags[0]), FC_GCM, testData1)
if err != nil {
	fmt.Errorf("Error Creating FileCrypt Block") 
}

// encrypt second block
err = fc.AddBlock([]byte(tags[1]), FC_CLEAR, testData2)
if err != nil {
	fmt.Errorf("Error Creating FileCrypt Block") 
}

// encrypt last block
err = fc.AddBlock([]byte(tags[2]), FC_GCM, testData3)
if err != nil {
	fmt.Errorf("Error Creating FileCrypt Block") 
}

// Decode filecrypt
newFC, err := NewFromFile("./testdata/sample1.dat")
if err != nil {
	fmt.Errorf("Error recovering FileCrypt Header") 
}

newTags := newFC.ListTags()
// Check Tags
for idx := 0; idx < len(tags); idx += 1 {
	if !bytes.Equal(newTags[idx], []byte(tags[idx])) {
               fmt.Errorf("Tags not equal")
	}
}
result, err := newFC.DecryptAll(key)
if err != nil {
	fmt.Errorf("Error Decrypting") 
}
if len(result) != 3 {
	fmt.Errorf("Unexpected result length")
}
r1 := *result[0].(*FCTest1)
r2 := *result[1].(*FCTest1)
r3 := *result[2].(*FCTest1)

if r1 != *testData1 {
	fmt.Errorf("Encrypted and decrypted values not equal")
}
if r2 != *testData2 {
	fmt.Errorf("Encrypted and decrypted values not equal")
}
if r3 != *testData3 {
	fmt.Errorf("Encrypted and decrypted values not equal")
}

for idx := 0; idx < len(tags); idx += 1 {
	result, err := newFC.DecryptSingle([]byte(tags[idx]), key)
	if err != nil {
	      fmt.Errorf("Error Decrypting") 
	}
	r := *result.(*FCTest1)
	if r != *testData[idx] {
	   fmt.Errorf("Encrypted and decrypted values not equal")
	}

}

```

