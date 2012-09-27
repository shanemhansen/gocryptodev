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
func NewCipher(ciphername CipherType, key []byte, iv []byte) (*Cipher, error) {
    handle, err := GetHandle()
    if err != nil {
        return nil, err
    }
    session := &SessionOp{Cipher: CRYPTO_AES_CBC}
    session.Key = unsafe.Pointer(&key[0])
    session.Keylen = uint32(len(key))
    err = ioctl(handle, CIOCGSESSION, unsafe.Pointer(session))
    if err != nil {
        return nil, err
    }
    cipher := &Cipher{File: handle, Session: session}
    cipher.CryptOp = &CryptOp{Session: session.Id}
    cipher.CryptOp.Flags = COP_FLAG_WRITE_IV
    if iv != nil {
        //Make a copy so the caller can reuse for decrypting
        new_iv := make([]byte, len(iv))
        copy(new_iv, iv)
        cipher.CryptOp.Iv = unsafe.Pointer(&new_iv[0])
    }
    return cipher, nil
}

//See crypto/cipher.Block.BlockSize
func (self *Cipher) BlockSize() int {
    return BlockSizes[self.Session.Cipher]
}

//The go convention for Encrypt is that it works
//one BlockSize at a time. Please use the BlockMode
//interface for performance as it can encrypt multiple blocks
func (self *Cipher) Encrypt(dst, src []byte) {
    self.encrypt(dst, src, false)
}

//Encrypt several blocks. Again this doesn't handle
//padding. So len(dst) % self.BlockSize must equal 0
func (self *Cipher) CryptBlocks(dst, src []byte) {
    self.encrypt(dst, src, true)
}
func (self *Cipher) encrypt(dst, src []byte, slurp bool) {
    op := self.CryptOp
    op.Operation = COP_ENCRYPT
    //For now, support ECB because everything else
    //can be layered on top in go.
    op.Src = unsafe.Pointer(&src[0])
    if slurp {
        op.Length = uint32(len(src))
    } else {
        op.Length = uint32(self.BlockSize())
    }
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
