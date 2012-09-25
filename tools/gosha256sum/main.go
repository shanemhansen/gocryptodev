package main

import "os"
import "fmt"

import "github.com/shanemhansen/gocryptodev"

func main() {
    h, err := gocryptodev.New(gocryptodev.CRYPTO_SHA2_256)
    if err != nil {
        panic(err)
    }
    buf := make([]byte, 1024*1024*2)
    for {
        n, err := os.Stdin.Read(buf)
        if err != nil {
            break
        }
        h.Write(buf[:n])
    }
    fmt.Printf("%x\n", h.Sum(nil))

}
