#ifndef __BLOCKCHAIN_H_
#define __BLOCKCHAIN_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <llist.h>
#include <openssl/sha.h>
#include <unistd.h>
#include "../../crypto/hblk_crypto.h"



typedef struct blockchain_s
{
	llist_t     *chain;
} blockchain_t;

#define BLOCKCHAIN_DATA_MAX 1024


typedef struct block_data_s
{
	
	int8_t      buffer[BLOCKCHAIN_DATA_MAX];
	uint32_t    len;
} block_data_t;


typedef struct block_info_s
{
	uint32_t    index;
	uint32_t    difficulty;
	uint64_t    timestamp;
	uint64_t    nonce;
	uint8_t     prev_hash[SHA256_DIGEST_LENGTH];
} block_info_t;


typedef struct block_s
{
	block_info_t    info; 
	block_data_t    data; 
	uint8_t     hash[SHA256_DIGEST_LENGTH];
} block_t;



#define UNUSED(x) (void)(x)

blockchain_t *blockchain_create(void);

#endif 
