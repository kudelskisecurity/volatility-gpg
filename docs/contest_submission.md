## Volatility plugin contest 2022 Submissions - GPG passphrase recovery plugin
### Nils Amiet and Sylvain Pelissier


## Abstract

Data decryption with GnuPG works the following: The first time the decryption is called, the system asks the user for their passphrase to decrypt the private key needed to decrypt the file.
Then for the subsequent decryptions, the passphrase is not asked but read from cache. This mechanism is also used for symmetric-key encryption.

The cache time to live has a default value of 10 minutes. After the time to live elapsed, the cached item is cleared from memory. To avoid having key material directly in cleartext in memory, GPG
encapsulates such key material before storing it in memory.

We wrote two Volatility3 plugins to demonstrate how to retrieve passphrases and encryption keys in cache from a memory dump.

## GPG passphrase recovery plugin

### gpg_partial 

### gpg_full

## Why we should win the contest?
