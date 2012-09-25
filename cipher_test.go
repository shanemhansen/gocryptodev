package gocryptodev

import "testing"
import "crypto/cipher"
import "bytes"
import "strings"
import "fmt"

var key = []byte("1234567890123456")
var cipher_results = map[CipherType]string{
    CRYPTO_AES_ECB: "bcbecadafbbe4f48be2c18e1e52ad502"}
var cleartext = []byte("shaner baner\nsha")

func TestCipher(t *testing.T) {
    var aes cipher.Block
    var err error
    for cipher_id, expected := range cipher_results {
        aes, err = NewCipher(cipher_id, key)
        if err != nil {
            t.Fatal(err)
        }
        blocksize := aes.BlockSize()
        ciphertext := make([]byte, blocksize)
        aes.Encrypt(ciphertext, cleartext)
        deciphertext := make([]byte, blocksize)
        if !strings.EqualFold(expected, fmt.Sprintf("%x", ciphertext)) {
            t.Fatal("couldn't encrypt")
        }
        aes.Decrypt(deciphertext, ciphertext)
        if !bytes.Equal(cleartext, deciphertext) {
            t.Fatal("couldn't decrypt %s %s", cleartext, deciphertext)
        }
        if err != nil {
            t.Fatal(err)
        }
    }
}
