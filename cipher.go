package gocryptodev

import "os"
import "fmt"
import "unsafe"
import "bytes"

type Cipher struct {
    File    *os.File
    Session *SessionOp
    CryptOp *CryptOp
}

//Create a new cipher See constants for possible cipher types
//CRYPTO_AES_ECB is probably what you want here. CBC, CTR
//behaviour can be added by passing this to crypto/cipher to
//create a StreamReader or StreamWriter
func NewCipher(ciphername CipherType, key []byte) (*Cipher, error) {
    handle, err := GetHandle()
    if err != nil {
        return nil, err
    }
    session := &SessionOp{Cipher: ciphername}
    session.Key = unsafe.Pointer(&key[0])
    session.Keylen = uint32(len(key))
    err = ioctl(handle, CIOCGSESSION, unsafe.Pointer(session))
    if err != nil {
        return nil, err
    }
    cipher := &Cipher{File: handle, Session: session}
    cipher.CryptOp = &CryptOp{Session: session.Id}
    return cipher, nil
}

//See crypto/cipher.Block.BlockSize
func (self *Cipher) BlockSize() int {
    return BlockSizes[self.Session.Cipher]
}

//Encrypt the data in src, placing the result in dst
//I believe for now src must be a multiple of the blocksize
//You're on your own for padding.
func (self *Cipher) Encrypt(dst, src []byte) {
    op := self.CryptOp
    op.Operation = COP_ENCRYPT
    //For now, support ECB because everything else
    //can be layered on top in go.
    op.Iv = nil
    op.Src = unsafe.Pointer(&src[0])
    op.Length = 16
    op.Dst = unsafe.Pointer(&dst[0])
    err := ioctl(self.File, CIOCCRYPT, unsafe.Pointer(op))
    if err != nil {
        //nothing else we can do : (
        panic(err)
    }
}

//Decrypt src placing the result in dst
func (self *Cipher) Decrypt(dst, src []byte) {
    op := self.CryptOp
    op.Operation = COP_DECRYPT
    //For now, support ECB because everything else
    //can be layered on top in go.
    op.Iv = nil
    op.Src = unsafe.Pointer(&src[0])
    op.Length = uint32(len(src))
    op.Dst = unsafe.Pointer(&dst[0])
    err := ioctl(self.File, CIOCCRYPT, unsafe.Pointer(op))
    if err != nil {
        //nothing else we can do : (
        panic(err)
    }
}

//Info returns some kernel data on the driver being used
//in the current session.
func (self *Cipher) Info() (string, error) {
    info := &SessionInfoOp{Session: self.Session.Id}
    err := ioctl(self.File, CIOCGSESSINFO, unsafe.Pointer(info))
    if err != nil {
        //nothing else we can do : (
        return "", err
    }
    //pull the c strings out.
    length := bytes.IndexByte(info.CipherInfo.CraName[:], 0x0)
    name := string(info.CipherInfo.CraName[:length])
    length = bytes.IndexByte(info.CipherInfo.CraDriverName[:], 0x0)
    driver_name := string(info.CipherInfo.CraName[:length])

    return fmt.Sprintf("Cipher: %s, Driver: %s", name, driver_name), nil
}
