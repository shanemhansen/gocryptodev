package main

import "os"
import "io"
import "fmt"

import "github.com/shanemhansen/gocryptodev"

func main() {
    h, err := gocryptodev.New(gocryptodev.CRYPTO_SHA2_512)
    if err != nil {
        panic(err)
    }
    io.Copy(h, os.Stdin)
    fmt.Printf("%x\n", h.Sum(nil))
}
