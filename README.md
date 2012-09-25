# Description
gocryptodev is a pure go (no-cgo) api for
the cryptodev (/dev/crypto) cryptography api.

It currently exposes a number of hash.Hash compatible
hashes as well as a cipher.Block compatible AES implementation.

None of the CBC or other modes are supported because go provides
wrappers for these.

## Installation

Install the cryptodev-linux module: http://home.gna.org/cryptodev-linux/
the standard make; sudo make install should work just fine.
insert the module and allow others to access it.

    sudo insmod /lib/modules/3.2.0-30-generic/extra/cryptodev.ko
    sudo chmod a+rw /dev/crypto

Install the package using a standard go get github.com/shanemhansen/gocryptodev

The tools directory contains replacements for several coreutils hashing programs
like sha1sum, sha256sum, etc.
    
## Bugs:

The contract for Hash.Sum() states that it can be
called multiple times. Due to limitations (I think)
of cryptodev, Sum() can only be called once. After that
you may issue a Reset and reuse the same hash.
