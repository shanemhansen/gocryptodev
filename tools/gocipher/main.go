package main

import "github.com/shanemhansen/gocryptodev"
import "os"

var BlockSize = 1024 * 64

func main() {
    key := make([]byte, 16)
    iv := make([]byte, 16)
    cipher, err := gocryptodev.NewCipher(gocryptodev.CRYPTO_AES_CBC, key, iv)
    if err != nil {
        panic(err)
    }
    buf := make([]byte, BlockSize)
    for {
        n, err := os.Stdin.Read(buf)
        if err != nil {
            break
        }
        cipher.CryptBlocks(buf, buf[:n])
        os.Stdout.Write(buf[:n])
    }
}
