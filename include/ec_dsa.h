#ifndef _EC_DSA_H_
#define _EC_DSA_H_

#include "../uint256_t/uint256_t.h"

uint256_t safe_random(uint256_t a, uint256_t b);
uint256_t hash_message(const uint256_t number);

std::pair<uint256_t, uint256_t> sign(uint256_t hashed, uint256_t private_key);
bool verify(uint256_t hashed, std::pair<uint256_t, uint256_t> siganture, std::pair<uint256_t, uint256_t> public_key);

#endif