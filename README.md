# go-backup
Identity Backup and Recovery Library

## Overview
Go-backup is a backup and retrieval library to demonstrate the how we could integrate this functionality into iden3's identity wallet.
This first version includes the basic functionality to:
* Generate a random finite field element that will be used as a Key. Finite field is configurable.
* Generate (N,k) Shares of this key using the specified secret sharing algorithm. For now, only Shamir's Secret sharing is implemented, where N is the maximum number of shares and k is the minimum number of shares required to regenerate the key.
* Generate the Key back using k Shares retrieved from Custodians.
* Encode shares into some bytestream format that can be later recovered.
* Generate a QR code with the Share bytestream.
* Decode the QR containing the Shares
* Encode an arbitrary number of data structures that we want to store in a backup file so that they can be later recovered
* Generate an Encryption key using some Key Derivation Scheme. For now, only PBKDF2 or direct Key methods are implemented, but they can be easily expanded
* Encrypt and decrypt data structures adding enough information in a header so that they can be later decrypted. Also, we allow to include information with no  encrpytion that can be recovered without a Key.




