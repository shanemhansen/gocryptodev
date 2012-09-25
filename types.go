package gocryptodev

import "unsafe"

//SessionOp is a session between you and the kernel. It determines
//the type of cipher or digest you are working with and the encryption key
type SessionOp struct {
    Cipher    CipherType
    Mac       DigestType
    Keylen    uint32
    Key       unsafe.Pointer
    Mackeylen uint32
    Mackey    unsafe.Pointer
    Id        uint32
}

//SessionInfoOp holds information about the current session
type SessionInfoOp struct {
    Session    uint32
    CipherInfo struct {
        CraName       [CRYPTODEV_MAX_ALG_NAME]byte
        CraDriverName [CRYPTODEV_MAX_ALG_NAME]byte
    }
    HashInfo struct {
        CraName       [CRYPTODEV_MAX_ALG_NAME]byte
        CraDriverName [CRYPTODEV_MAX_ALG_NAME]byte
    }
    AlignMask uint32
    Flags     uint32
}

//CryptOp is what is passed to the kernel each time a encrypt/decrypt/hash
//request is made.
type CryptOp struct {
    Session   uint32
    Operation uint16
    Flags     uint16
    Length    uint32
    Src       unsafe.Pointer
    Dst       unsafe.Pointer
    Mac       unsafe.Pointer
    Iv        unsafe.Pointer
}
