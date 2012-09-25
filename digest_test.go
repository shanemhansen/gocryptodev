package gocryptodev

import "testing"
import "strings"
import "fmt"
import "hash"

var results = map[DigestType]string{
    CRYPTO_SHA1:     "9bd1ed1986caa5fc1a02ad5628ebcbf6e6010182",
    CRYPTO_SHA2_256: "b13d431fc4b21255f2b575ce39042cbe4e5746799dc9d07ad1f93d1579e9ae5c",
    CRYPTO_SHA2_384: "53044c07ba8a92631713fa876fd91594fe0c627e32e2a880af3531db850b449e2e9e361c1a87238d697cef4d676814e2",
    CRYPTO_SHA2_512: "25fe29dd4d7f928e877fd448808837c1e985b90fce199752398d0832bb09425f61b27040e6379284e31d7af4f990679c9826e6856119ce30d4148e2209837ee6",
    CRYPTO_MD5:      "c258746630353b29400d0e17c1f3832f"}

func TestHASH(t *testing.T) {
    for hash_id, expected := range results {
        //Just here to enforce that we are hash.Hash compatible
        var h hash.Hash
        h, err := New(hash_id)
        if err != nil {
            t.Fatal(err)
        }
        msg := []byte("shaner baner\n")
        msg2 := []byte("shaner baner")
        h.Write(msg)
        h.Write(msg2)
        encoded := h.Sum(nil)
        if err != nil {
            t.Fatal(err)
        }
        if !strings.EqualFold(expected, fmt.Sprintf("%x", encoded)) {
            t.Fatalf("%x|%s", encoded, expected)
        }
    }
}

func TestHASHReset(t *testing.T) {
    h, err := New(CRYPTO_SHA1)
    if err != nil {
        t.Fatal(err)
    }
    msg := []byte("shaner baner\n")
    msg2 := []byte("shaner baner")
    h.Write(msg)
    h.Write(msg2)
    h.Reset()
    encoded := h.Sum(nil)
    if strings.EqualFold(results[CRYPTO_SHA1], fmt.Sprintf("%x", encoded)) {
        t.Fatal("Results should not be equal")
    }

}
