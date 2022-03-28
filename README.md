# Volatility3 gpg passphrase recovery plugin

This repository contains Volatility3 plugins that can retrieve partial and full gpg passphrases from `gpg-agent`'s cache.

`gpg_partial.py` may retrieve at most 8 characters from a passphrase for gnupg using versions of libgcrypt [older than 1.8.9](https://dev.gnupg.org/T5597).

## Installation

Pass this directory as plugin directory using the `-p` option when using volatility3 (see examples below).

Use either the `linux.gpg_partial` or the `linux.gpg_full` plugins.

Make sure to use the latest git version of volatility3: https://github.com/volatilityfoundation/volatility3

```
mkdir ~/git
cd ~/git
git clone https://github.com/volatilityfoundation/volatility3

```

### Usage


Just before capturing the memory dump, a file was symmetrically encrypted with gpg. When prompted, we enter a passphrase of our choice:

```
echo "some text that we want to encrypt" > cleartext.txt
gpg --symmetric --cipher-algo AES-256 -o out.enc cleartext.txt
gpg -d out.enc
```

We chose a passphrase that is longer than 8 characters: `verylongpassphrase*!!`.

A memory dump can be obtained, for example, using [LiME](https://github.com/504ensicsLabs/LiME).
Volatility3 will also require the corresponding symbols, which can be generated [as explained here](https://volatility3.readthedocs.io/en/latest/symbol-tables.html).

Using the `gpg_partial` plugin, only the first 8 characters can be retrieved:

```
$ ~/git/volatility3/vol.py -f memdump-gpg-verylongpassphrasestarexclexcl -s symbols/ -p ~/git/volatility-gpg/ linux.gpg_partial
Volatility 3 Framework 2.0.0
Progress:  100.00               Stacking attempts finished                 
Offset  Partial GPG passphrase (max 8 chars)

0x7fb04caee2a0  verylong

```

With the `gpg_full` plugin, the full passphrase can be retrieved:

```
$ ~/git/volatility3/vol.py -f memdump-gpg-verylongpassphrasestarexclexcl -s symbols/ -p ~/git/volatility-gpg/ linux.gpg_full --fast --epoch 1638107484
Volatility 3 Framework 2.0.0
Progress:  100.00               Stacking attempts finished                 
Offset  Private key     Secret size     Plaintext
Searching from 28 Nov 2021 14:51:24 to 10 Jun 2022 20:11:39

0x7fb048002578  788dc61976e3ac8e9e10d7b80b3e7b40        32      verylongpassphrase*!!
0x7fb048002578  788dc61976e3ac8e9e10d7b80b3e7b40        32      verylongpassphrase*!!
```

