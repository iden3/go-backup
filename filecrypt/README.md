
# Filecrypt
Package filecrypt implements filecrypt encryption and decryption protocol

Filecrypt procotol is used to encrypt a set of different data structures
into a file. It adds enough information in a header to be able to decrypt it 
at a later time.

A filecrypt block includes a  Key Header, a Encryption header, and a sequence of payload blocks. There may be multiple filecrypt blocks with different encryption options. Typically, a filecrypt block includes a single data structure. Multiple filecrypt blocks can be appended toguether to encrypt several data structures with different Encryption Headers.

Both Key Header and Encryption Header are always unencrypted. 
Payload blocks may or may not be encryted.

**NOTE** Before using filecrypt, you should call *gob.Register()* function to register the data strcutre you want to backup

Filecrypt currently supports two encryption schemes:
- GCM : Symmetric Encryption
- RSA : Asymmetric Encryption

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

Currently No Hash (*FC_NOHASH*), SHA1 (*FC_HASH_SHA1*), SHA256 (*FC_HASH_SHA256*) are implemented as hash functions



## Encryption Header Format
Encryption Header is 16 bytes long. Contents include

|Field | Length | Description |
|------|--------|-------------|
| **Version** | 1 Byte | Version 0 |
| **BlockType** | 1 Byte | Indicates if block is First (*FC_HDR_BIDX_FIRST*), Middle (*FC_HDR_BIDX_MID*), Last(*FC_HDR_BIDX_LAST*) or it is a single block (*FC_HDR_BIDX_SINGLE*) | 
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
test_msg1 := FCTest{SecretText : "This is a test", }
test_msg2 := FCTest{SecretText :"This is also a test", }
test_msg3 := FCTest{SecretText :"This is not a test", }

// register struct
gob.Register(&FCTest{})


// init 256 bit key
key := make([]byte, 32)
if _, err := io.ReadFull(rand.Reader, key); err != nil {
		fmt.Errorf("Error generating key")
}


// init key hdr
hdr_k := &DirectKeyFc{}
hdr_k.FillHdr(TEST_VERSION, FC_KEY_T_DIRECT, key)


// encrypt first block
hdr_e := &GcmFc{}
hdr_e.FillHdr(0, FC_GCM, FC_BSIZE_BYTES_256, FC_HDR_BIDX_FIRST)

err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data1)
if err != nil {
	fmt.Println("Error encrypting block")
}

// encrypt second block
hdr_e.FillHdr(0, FC_GCM, FC_BSIZE_BYTES_256, FC_HDR_BIDX_MID)
err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data2fmt.Println("Error encrypting block")})
if err != nil {
		fmt.Println("Error encrypting block")

}

// encrypt last block
hdr_e.FillHdr(0, FC_GCM, FC_BSIZE_BYTES_256, FC_HDR_BIDX_LAST)
err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data3)
if err != nil {
	fmt.Println("Error encrypting block")

}

// Decrypt
result, err := Decrypt("./testdata/sample1.dat", key)
if err != nil {
	fmt.Println("Error decrypting block")

}

r1 := *result[0].(*FCTest)
r2 := *result[1].(*FCTest)
r3 := *result[2].(*FCTest)

```

### Mixed No encryption and GCM with PBKDF2 
In this example we will encrypt the first and third blocks with GCM-256 using PBKDF2 key derivation function and the second block will be unencrypted.

```
type FCTest struct{
   SecretText string
}

// init tests data
test_msg1 := FCTest{SecretText : "This is a test", }
test_msg2 := FCTest{SecretText :"This is also a test", }
test_msg3 := FCTest{SecretText :"This is not a test", }

// register struct
gob.Register(&FCTest{})


// init 256 bit key
key := make([]byte, 32)
if _, err := io.ReadFull(rand.Reader, key); err != nil {
		fmt.Errorf("Error generating key")
}


// init key hdr
hdr_k := &Pbkdf2Fc{}
hdr_k.FillHdr(	
                0,	               // version
                FC_KEY_T_PBKDF2,
                FC_HASH_SHA256,
                60000,               // n iter
	        FC_BSIZE_BYTES_256,
		12 ,                 // salt length
		key
)



// encrypt first block
hdr_e := &GcmFc{}
hdr_e.FillHdr(TEST_VERSION, FC_GCM, FC_BSIZE_BYTES_256, FC_HDR_BIDX_FIRST)

err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data1)
if err != nil {
	fmt.Println("Error encrypting block")
}

// encrypt second block
hdr_e.FillHdr(TEST_VERSION, FC_CLEAR, FC_BSIZE_BYTES_256, FC_HDR_BIDX_MID)
err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data2fmt.Println("Error encrypting block")})
if err != nil {
		fmt.Println("Error encrypting block")

}

// encrypt last block
hdr_e.FillHdr(TEST_VERSION, FC_GCM, FC_BSIZE_BYTES_256, FC_HDR_BIDX_LAST)
err = Encrypt(hdr_k, hdr_e, "./testdata/sample1.dat", test_data3)
if err != nil {
	fmt.Println("Error encrypting block")

}

// Decrypt
result, err := Decrypt("./testdata/sample1.dat", key)
if err != nil {
	fmt.Println("Error decrypting block")

}

r1 := *result[0].(*FCTest)
r2 := *result[1].(*FCTest)
r3 := *result[2].(*FCTest)

```

