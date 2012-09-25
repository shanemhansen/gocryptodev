/*
Package gocryptodev provides an interface to /dev/crypto, sometimes known
as the OCF (OpenBSD Cryptography Framework). A userspace mechanism for exposing
hardware accelerated crypto engines in the kernel such as those found in marvell
kirkwood platform. This package is pure go (no cgo) which makes cross compiling
for arm platforms a breeze.


This package exposes 2 primary Structures, a Hash which is (mostly) hash.Hash compatible and a cipher.Block. cryptodev provides the common hashes (md5, sha1, sha256) and AES. Most of these low level primitives are meant to be used with the go stream creating functions under crypto/hmac or crypto/cipher.
*/
package gocryptodev

import "os"
import "unsafe"
import "crypto"
import "hash"
import "bytes"
import "fmt"
import "errors"

//Type Hash is a hash.Hash compatible object for hashing data.
type Hash struct {
    File    *os.File
    Session *SessionOp
    CryptOp *CryptOp
    Digest  []byte
    Fired   bool
}

var cryptodev *os.File

var MultipleSumNotSupported = errors.New("We don't support calling sum multiple times")

//RegisterHashes uses go's pluggable hash registry to add gocryptodev
//hashes as the default hash implementation.
func RegisterHashes() {
    digest, err := New(CRYPTO_MD5)
    if err != nil {
        crypto.RegisterHash(crypto.MD5, func() hash.Hash {
            return digest
        })
    }
    digest, err = New(CRYPTO_SHA1)
    if err == nil {
        crypto.RegisterHash(crypto.SHA1, func() hash.Hash {
            return digest
        })
    }
    digest, err = New(CRYPTO_SHA2_256)
    if err == nil {
        crypto.RegisterHash(crypto.SHA256, func() hash.Hash {
            return digest
        })
    }
    digest, err = New(CRYPTO_SHA2_384)
    if err == nil {
        crypto.RegisterHash(crypto.SHA384, func() hash.Hash {
            return digest
        })
    }
    digest, err = New(CRYPTO_SHA2_512)
    if err == nil {
        crypto.RegisterHash(crypto.SHA512, func() hash.Hash {
            return digest
        })
    }
    digest, err = New(CRYPTO_RIPEMD160)
    if err == nil {
        crypto.RegisterHash(crypto.RIPEMD160, func() hash.Hash {
            return digest
        })
    }

}

//A helper function which manages a singleton
//instance of the cryptodev handle. access is multiplexed
//via multiple sessions (Hash/Digest) objects.
func GetHandle() (*os.File, error) {
    var err error
    if cryptodev != nil {
        return cryptodev, nil
    }
    cryptodev, err = os.Open("/dev/crypto")
    if err != nil {
        return nil, err
    }
    return cryptodev, nil
}

//Create a new digest of the given type
func New(digestType DigestType) (*Hash, error) {
    handle, err := GetHandle()
    if err != nil {
        return nil, err
    }
    session := &SessionOp{Mac: digestType}
    err = ioctl(handle, CIOCGSESSION, unsafe.Pointer(session))
    if err != nil {
        return nil, err
    }
    hash := &Hash{File: handle, Session: session}
    if err != nil {
        return nil, err
    }
    //big enough for anything
    hash.Digest = make([]byte, 512/8)
    hash.CryptOp = &CryptOp{Session: session.Id}
    hash.CryptOp.Mac = unsafe.Pointer(&hash.Digest[0])
    return hash, nil
}

//Write the bytes to the hash.
func (self *Hash) Write(buf []byte) (int, error) {
    length := len(buf)
    if length == 0 {
        return 0, nil
    }
    op := self.CryptOp
    op.Flags = COP_FLAG_UPDATE
    op.Length = (uint32)(length)
    op.Src = unsafe.Pointer(&buf[0])
    err := ioctl(self.File, CIOCCRYPT, unsafe.Pointer(op))
    if err != nil {
        return 0, err
    }
    return length, nil
}

//Write buf to the hash and return the digest
//Unfortunately Sum may only be called once per stream. Call Reset in order to reuse the hash
//on new data
func (self *Hash) Sum(buf []byte) []byte {
    if buf != nil && len(buf) != 0 {
        self.Write(buf)
    }
    if self.Fired {
        panic(MultipleSumNotSupported)
    }
    self.Fired = true
    op := self.CryptOp
    op.Flags = COP_FLAG_FINAL
    op.Length = 0
    //Write final digest
    err := ioctl(self.File, CIOCCRYPT, unsafe.Pointer(op))
    if err != nil {
        panic(err)
    }
    //End session
    err = ioctl(self.File, CIOCFSESSION, unsafe.Pointer(self.Session))
    if err != nil {
        panic(err)
    }
    //Make sure it's unusable
    self.Session.Id = 0
    return self.Digest[:self.BlockSize()]
}

//See hash.Hash.BlockSize
func (self *Hash) BlockSize() int {
    return BlockSizes[self.Session.Mac]
}

//Reset reset's a hashes state for resuse
func (self *Hash) Reset() {
    op := self.CryptOp
    op.Flags = COP_FLAG_RESET
    err := ioctl(self.File, CIOCCRYPT, unsafe.Pointer(op))
    if err != nil {
        panic(err)
    }
    self.Fired = false

}

//See hash.Hash.Size
func (self *Hash) Size() int {
    return BlockSizes[self.Session.Mac]
}

//Expose the CIOCGSESSINFO data which includes driver information
//Sometimes helpful in determining whether a given cipher is actually
//being hardware accelerated or just done in-kernel.
func (self *Hash) Info() (string, error) {
    info := &SessionInfoOp{Session: self.Session.Id}
    err := ioctl(self.File, CIOCGSESSINFO, unsafe.Pointer(info))
    if err != nil {
        //nothing else we can do : (
        return "", err
    }
    //pull the c strings out.
    length := bytes.IndexByte(info.HashInfo.CraName[:], 0x0)
    name := string(info.HashInfo.CraName[:length])
    length = bytes.IndexByte(info.HashInfo.CraDriverName[:], 0x0)
    driver_name := string(info.HashInfo.CraName[:length])
    return fmt.Sprintf("Cipher: %s, Driver: %s", name, driver_name), nil
}
