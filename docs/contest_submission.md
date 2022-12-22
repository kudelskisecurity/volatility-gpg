## Volatility plugin contest 2022 Submissions - GPG passphrase recovery plugin
### Nils Amiet and Sylvain Pelissier


## Abstract

Data decryption with GnuPG works the following: The first time the decryption is called, the system asks the user for their passphrase to decrypt the private key needed to decrypt the file.
Then for the subsequent decryptions, the passphrase is not asked but read from cache. This mechanism is also used for symmetric-key encryption.

The cache time to live has a default value of 10 minutes. After the time to live elapsed, the cached item is cleared from memory. To avoid having key material directly in cleartext in memory, GPG
encapsulates such key material before storing it in memory.

We wrote two Volatility3 plugins to demonstrate how to retrieve passphrases and encryption keys in cache from a memory dump.

The full description of the cache encryption is given in the paper joint to this email which we have presented during the SSTIC and NullCon conferences (https://nullcon.net/berlin-2022/GPG-memory-forensics).

## GPG passphrase recovery plugin

We developed two plugins for Volatility3 available at https://github.com/kudelskisecurity/volatility-gpg which have been tested with Volatility3 framework version 2.4.0.

### gpg_partial

The first plugin retrieves partial (or complete, up to 8 characters) passphrases from memory by searching
in `gpg-agent`'s memory the constant IV of aes-wrap. This plugin would not work on versions of GPG later than version 2.3.4.
Here is an example of usage:

```
$ ~/git/volatility3/vol.py -f memdump-gpg-verylongpassphrasestarexclexcl -s symbols/ -p ~/git/volatility-gpg/ linux.gpg_partial
Volatility 3 Framework 2.0.0
Progress:  100.00               Stacking attempts finished                 
Offset  Partial GPG passphrase (max 8 chars)

0x7fb04caee2a0  verylong
```

The first 8 bytes of the passphrase were found in clear in memory.

### gpg_full

The second plugin retrieves cached items in memory and cache encryption keys and therefore helps recover plaintexts.
An example of usage is shown below, where the plugin successfully found the entire passphrase `verylongpassphrase*!!` 
in memory. The first plugin execution took 6.4 seconds and the second 59.7 seconds on an Intel Core i7-7600U CPU for a 1GB RAM dump.

```
$ ~/git/volatility3/vol.py -f memdump-gpg-verylongpassphrasestarexclexcl -s symbols/ -p ~/git/volatility-gpg/ linux.gpg_full --fast --epoch 1638107484
Volatility 3 Framework 2.0.0
Progress:  100.00               Stacking attempts finished                 
Offset  Private key     Secret size     Plaintext
Searching from 28 Nov 2021 14:51:24 to 10 Jun 2022 20:11:39

0x7fb048002578  788dc61976e3ac8e9e10d7b80b3e7b40        32      verylongpassphrase*!!
0x7fb048002578  788dc61976e3ac8e9e10d7b80b3e7b40        32      verylongpassphrase*!!
```

The estimated epoch time around which the gpg-agent cache item was created can be passed as a parameter 
using the --epoch option. If it is not passed, the current time is used by default. Note that it is important 
to pass the right epoch time because only cache items created in the searched time range may be recovered.

## Why we should win the contest?

We have used the Volatility3 framework to demonstrate how the cache of GnuPG can be analyzed to decrypt and recover 
passphrases stored. By publishing our plugin code, we would like to help the forensics community by making their 
work easier. We hope this gives a starting point for people who want to analyze other solutions 
caching secrets in memory in an unsafe way.
GPG is a widely used software, and we think that these plugins can therefore help a wide array of people.