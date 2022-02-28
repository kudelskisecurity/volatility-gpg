# Volatility3 gpg passphrase recovery plugin

This repository contains volatility3 plugins that can retrieve partial and full gpg passphrases.

`gpg_partial.py` may retrieve at most 8 characters from a passphrase for gnupg using versions of libgrypt older than 1.8.9.

## Usage

Pass this directory (or simply this directory) using the `-p` option when using volatility (see examples below).

### Examples


Just before capturing the memory dump, a file was symmetrically encrypted with gpg. When prompted, we enter a passphrase of our choice:

```
echo "some text that we want to encrypt" > cleartext.txt
gpg --symmetric --cipher-algo AES-256 -o out.enc cleartext.txt
gpg -d out.enc
```

Here the passphrase was `verylongpassphrase*!!`. Only the first 8 characters can be retrieved:

```
$ vol -f memdump-gpg-verylongpassphrasestarexclexcl -s symbols/ -p ~/git/gpg-mem-forensics/volatility-gpg/ linux.gpg_passphrase
Volatility 3 Framework 1.0.1
Progress:  100.00               Stacking attempts finished                 
Offset  Partial GPG passphrase (max 8 chars)

0x6a032a0       verylong
0x10a4b300      verylong
```

Here the passphrase is `dapass42`, since it's no more than 8 characters, it can be fully retrieved:

```
$ vol -f memdump-gpg-dapass42 -s symbols/ -p ~/git/gpg-mem-forensics/volatility-gpg/ linux.gpg_passphrase
Volatility 3 Framework 1.0.1
Progress:  100.00               Stacking attempts finished                 
Offset  Partial GPG passphrase (max 8 chars)

0x6a032a0       dapass42
```
