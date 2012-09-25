package gocryptodev

const (
    CRYPTO_HMAC_MAX_KEY_LEN   = 512
    CRYPTO_CIPHER_MAX_KEY_LEN = 64
)

type DigestType uint32
type CipherType uint32

//Various digests and ciphers supported by cryptodev. Not all of these
//are usable (such as those requiring iv's. To get hmac or cbc please pass
//a Hash or Cipher to crypto/hmac or crypto/cipher

const (
    CRYPTO_DES_CBC         = iota
    CRYPTO_3DES_CBC        = iota
    CRYPTO_BLF_CBC         = iota
    CRYPTO_CAST_CBC        = iota
    CRYPTO_SKIPJACK_CBC    = iota
    CRYPTO_MD5_HMAC        = iota
    CRYPTO_SHA1_HMAC       = iota
    CRYPTO_RIPEMD160_HMAC  = iota
    CRYPTO_MD5_KPDK        = iota
    CRYPTO_SHA1_KPDK       = iota
    CRYPTO_RIJNDAEL128_CBC = iota
    CRYPTO_AES_CBC         = CRYPTO_RIJNDAEL128_CBC
    CRYPTO_ARC4            = iota
    CRYPTO_MD5             = iota
    CRYPTO_SHA1            = iota
    CRYPTO_DEFLATE_COMP    = iota
    CRYPTO_NULL            = iota
    CRYPTO_LZS_COMP        = iota
    CRYPTO_SHA2_256_HMAC   = iota
    CRYPTO_SHA2_384_HMAC   = iota
    CRYPTO_SHA2_512_HMAC   = iota
    CRYPTO_AES_CTR         = iota
    CRYPTO_AES_XTS         = iota
    CRYPTO_AES_ECB         = iota
    CRYPTO_AES_GCM         = 50
    CRYPTO_CAMELLIA_CBC    = 101
    CRYPTO_RIPEMD160       = 102
    CRYPTO_SHA2_256        = 103
    CRYPTO_SHA2_384        = 104
    CRYPTO_SHA2_512        = 105
    CRYPTO_ALGORITHM_ALL   = 106
)

const (
    DES_BLOCK_LEN          = 8
    DES3_BLOCK_LEN         = 8
    RIJNDAEL128_BLOCK_LEN  = 16
    AES_BLOCK_LEN          = RIJNDAEL128_BLOCK_LEN
    CAMELLIA_BLOCK_LEN     = 16
    BLOWFISH_BLOCK_LEN     = 8
    SKIPJACK_BLOCK_LEN     = 8
    CAST128_BLOCK_LEN      = 8
    EALG_MAX_BLOCK_LEN     = 16
    AALG_MAX_RESULT_LEN    = 64
    CRYPTODEV_MAX_ALG_NAME = 64
    HASH_MAX_LEN           = 64
)

const (
    COP_ENCRYPT = 0
    COP_DECRYPT = 1
)

const (
    COP_FLAG_NONE           = 0 << 0
    COP_FLAG_UPDATE         = 1 << 0
    COP_FLAG_FINAL          = 1 << 1
    COP_FLAG_WRITE_IV       = 1 << 2
    COP_FLAG_NO_ZC          = 1 << 3
    COP_FLAG_AEAD_TLS_TYPE  = 1 << 4
    COP_FLAG_AEAD_SRTP_TYPE = 1 << 6
    COP_FLAG_RESET          = 1 << 6
)

//Flags determining mode of operation of ciphers. You probably
//won't need to mess with these unless you are exposing new ciphers.

//Some useful lookup functions
var BlockSizes = []int{CRYPTO_SHA1: 20,
    CRYPTO_SHA2_256:  32,
    CRYPTO_SHA2_384:  48,
    CRYPTO_SHA2_512:  64,
    CRYPTO_MD5:       16,
    CRYPTO_AES_ECB:   AES_BLOCK_LEN,
    CRYPTO_RIPEMD160: 20}
