#ifndef HBLK_CRYPTO_H
#define HBLK_CRYPTO_H


#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#define EC_CURVE   NID_secp256k1

#define EC_PUB_LEN 65

#define SIG_MAX_LEN    72

#define PRI_FILENAME   "key.pem"
#define PUB_FILENAME   "key_pub.pem"

uint8_t *sha256(int8_t const *s, size_t len, uint8_t digest[SHA256_DIGEST_LENGTH]);

#endif
