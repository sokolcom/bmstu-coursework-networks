#include <iostream>
#include <stdexcept>
#include <memory>
#include <utility>
#include <string>

#include <openssl/rand.h>

#include "../include/define.h"
#include "../include/ec_dsa.h"
#include "../uint256_t/uint256_t.h"


const uint256_t field_modulo = FIELD_MODULO;
const uint256_t subgroup_order = SUBGROUP_ORDER;
const std::pair<uint256_t*, uint256_t*> base_point = std::make_pair(
    &uint256_t(BASE_POINT_X),
    &uint256_t(BASE_POINT_Y)
);


uint256_t safe_random(uint256_t& a, uint256_t& b) {
    uint8_t buffer[BYTES_PER_256_BIT] = { 0 };
    int8_t code = RAND_bytes(buffer, 32);
    if (code != 1) {
        throw std::runtime_error("Error!\nOpenSSL function failed!");
    }

    uint256_t x;
    x.from_bytes(buffer);
    for (; (x < a) && (x > b); RAND_bytes(buffer, 32), x.from_bytes(buffer));

    const uint256_t modulo = FIELD_MODULO;
    return x % modulo;
}

static uint256_t inverse_modulo(const uint256_t& x, const uint256_t& modulo) {
    // Fermat's little theorem
    return x.powmod(modulo - 2, modulo);
}

static std::pair<uint256_t*, uint256_t*> add(std::pair<uint256_t*, uint256_t*>& point_1, std::pair<uint256_t*, uint256_t*>& point_2) {
    if (!point_1.first) {
        return point_2;
    }
    if (!point_2.first) {
        return point_1;
    }

    uint256_t x1 = *point_1.first, y1 = *point_1.second;
    uint256_t x2 = *point_2.first, y2 = *point_2.second;
    
    // P + (-P) = 0
    if ((x1 == x2) && (y1 != y2)) {
        return std::make_pair(nullptr, nullptr);
    }

    uint256_t slope;
    // P1 = P2
    if (x1 == x2) {
        slope = (3 * x1 * x1 + 2 * _CURVE_A * x1 + _CURVE_B) * inverse_modulo(2 * y1, field_modulo);
    } else {
        slope = (y1 - y2) * inverse_modulo(x1 - x2, field_modulo);
    }

    uint256_t x3 = (slope * slope - CURVE_A - x1 - x2) % field_modulo;
    uint256_t y3 = (y1 + slope * (x3 - x1));
    y3 = -y3 % field_modulo;
    return std::make_pair(&x3, &y3);
}

static std::pair<uint256_t*, uint256_t*> scalar_mult(uint256_t& k, std::pair<uint256_t*, uint256_t*>& point) {
    std::pair<uint256_t*, uint256_t*> r0 = point;
    std::pair<uint256_t*, uint256_t*> r1 = add(point, point);

    // Montgomery ladder
    for (int16_t idx = k.bits() - 2; idx > -1 ; idx--) {
        if ((k >> idx) & 1) {
            r0 = add(r0, r1);
            r1 = add(r1, r1);
        } else {
            r1 = add(r0, r1);
            r0 = add(r0, r0);
        }
    }

    return r0;
}


std::pair<uint256_t&, uint256_t&> sign(std::string& message, uint256_t& private_key) {
    // uint256_t hashed = hash_message(message);

    uint256_t r = 0x0;
    uint256_t s = 0x0;
    while (!r || !s) {
        uint256_t k = cfg.safe_random(uint256_1, subgroup_order);
        std::pair<uint256_t*, uint256_t*> point =  scalar_mult(k, base_point);
        uint256_t r = *point.first % subgroup_order;
        uint256_t s = ((hashed + r * private_key) * inverse_modulo(k, subgroup_order)) % subgroup_order;
    }

    return std::make_pair(r, s);
}

bool verify(std::string& message, 
            std::pair<uint256_t&, uint256_t&> siganture,
            std::pair<uint256_t&, uint256_t&> public_key) {
    
    uint256_t r = siganture.first, s = siganture.second;
    // uint256_t hashed = hash_message(message);

    uint256_t inv_s = inverse_modulo(s, subgroup_order);
    uint256_t u1 = (inv_s * hashed) % subgroup_order;
    uint256_t u2 = (inv_s * r) % subgroup_order;
    std::pair<uint256_t*, uint256_t*> point = add(scalar_mult(u1, base_point), scalar_mult(u2, public_key));

    return (r % subgroup_order) == (*point.first % subgroup_order);

}
