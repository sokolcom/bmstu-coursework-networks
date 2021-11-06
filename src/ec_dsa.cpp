#include <iostream>
#include <stdexcept>
#include <memory>
#include <utility>
#include <string>

#include <openssl/rand.h>

#include "../include/define.h"
#include "../include/ec_dsa.h"
#include "../uint256_t/uint256_t.h"
#include "../sha256/include/SHA256.h"


#define PERSON_PRIVATE_KEY "0x631ee57d7cb6801890415ccc4622a12ddc0d0025ef087ce0e2798941473d142"
// #define CAR_PUBLIC_KEY_FIRST "0x7630498e5e4df030aedb1b0ea44ee1ce2a323427aaf2a959d9d31e39da843361"
// #define CAR_PUBLIC_KEY_SECOND "0x51859ccdf5567141f640eeefae2eddc4e1b1696149d8564a9a4ae7f756f32dc7"
#define CAR_PUBLIC_KEY_FIRST "0x7630498e5e4df030aedb1b0ea44ee1ce2a323427aaf2a959d9d31e39da843361"
#define CAR_PUBLIC_KEY_SECOND "0x51859ccdf5567141f640eeefae2eddc4e1b1696149d8564a9a4ae7f756f32dc7"


const uint256_t field_modulo = uint256_t(FIELD_MODULO);
const uint256_t subgroup_order = uint256_t(SUBGROUP_ORDER);
std::pair<uint256_t, uint256_t> base_point = std::make_pair(BASE_POINT_X, BASE_POINT_Y);


uint256_t safe_random(const uint256_t a, const uint256_t b) {
    uint8_t buffer[BYTES_PER_256_BIT] = { 0 };
    int8_t code = RAND_bytes(buffer, 32);
    if (code != 1) {
        throw std::runtime_error("Error!\nOpenSSL function failed!");
    }

    uint256_t x;
    x.from_bytes(buffer);
    for (; (x < a) || (x > b); RAND_bytes(buffer, 32), x.from_bytes(buffer));

    const uint256_t modulo = FIELD_MODULO;
    return x % modulo;
}

uint256_t hash_message(const uint256_t number) {
	SHA256 sha;
	sha.update(number.str(16,64));
    return uint256_t(SHA256::toString(sha.digest()));
}

static uint256_t inverse_modulo(const uint256_t x, const uint256_t modulo) {
    // // Fermat's little theorem
    return x.powmod(modulo - 2, modulo);
    
    // uint256_t s = 0, old_s = 1;
    // uint256_t t = 1, old_t = 0;
    // uint256_t r = modulo, old_r = x;

    // while (r) {
    //     uint256_t quotient = old_r / r;
    //     uint256_t temp1, temp2;

    //     temp1 = old_r;
    //     old_r = r;
    //     temp2 = quotient.mulmod(r, modulo);
    //     r = (temp1 > temp2) ? (temp1 - temp2) : modulo - (temp2 - temp1);
    //     // old_r, r = r, old_r - quotient * r;

    //     temp1 = old_s;
    //     old_s = s;
    //     temp2 = quotient.mulmod(s, modulo);
    //     s = (temp1 > temp2) ? (temp1 - temp2) : modulo - (temp2 - temp1);
    //     // old_s, s = s, old_s - quotient * s;

    //     temp1 = old_t;
    //     old_t = t;
    //     temp2 = quotient.mulmod(t, modulo);
    //     s = (temp1 > temp2) ? (temp1 - temp2) : modulo - (temp2 - temp1);
    //     // old_t, t = t, old_t - quotient * t;
    // }

    // uint256_t xxx = old_s;  // (x * k) % p == 1
    // return xxx % modulo;
}

static std::pair<uint256_t, uint256_t> add(std::pair<uint256_t, uint256_t>& point_1, std::pair<uint256_t, uint256_t>& point_2) {
    if (!point_1.first) {
        return point_2;
    }
    if (!point_2.first) {
        return point_1;
    }

    uint256_t x1 = point_1.first, y1 = point_1.second;
    uint256_t x2 = point_2.first, y2 = point_2.second;
    
    // P + (-P) = 0
    if ((x1 == x2) && (y1 != y2)) {
        return std::make_pair(0, 0);
    }

    uint256_t slope;
    uint256_t tempx, tempy, temp;
    uint256_t ca = uint256_t(_CURVE_A), cb = uint256_t(_CURVE_B);
    // P1 = P2
    if (x1 == x2) {
        uint256_t a = x1.mulmod(x1, field_modulo);  // 3*x1*x1
        a = a.mulmod(3, field_modulo);

        uint256_t b = x1.mulmod(ca, field_modulo);  // 2*x1*_CURVE_A
        b = b.mulmod(2, field_modulo);
        b = b.addmod(cb, field_modulo);

        a = a.addmod(b, field_modulo);
        temp = y1.mulmod(2, field_modulo);
        temp = inverse_modulo(temp, field_modulo);
        slope =  a.mulmod(temp, field_modulo);
    } else {
        tempx = (x1 > x2) ? (x1 - x2) : field_modulo - (x2 - x1);
        tempy = (y1 > y2) ? (y1 - y2) : field_modulo - (y2 - y1);
        tempx = inverse_modulo(tempx, field_modulo);
        slope = tempy.mulmod(tempx, field_modulo);
    }

    temp = slope.mulmod(slope, field_modulo);
    tempx = x2.addmod(ca, field_modulo);
    tempx = tempx.addmod(x1, field_modulo);  
    uint256_t x3 = (temp > tempx) ? (temp  - tempx) : field_modulo - (tempx - temp);  // (slope * slope - _CURVE_A - x1 - x2)% field_modulo;

    tempy = (x3 > x1) ? (x3 - x1) : field_modulo - (x1 - x3);
    tempy = tempy.mulmod(slope, field_modulo);
    uint256_t y3 =  y1.addmod(tempy, field_modulo);  // (y1 + slope * (x3 - x1));
    y3 = (field_modulo - y3) % field_modulo;

    return std::make_pair(x3, y3);
}

static std::pair<uint256_t, uint256_t> scalar_mult(uint256_t k, std::pair<uint256_t, uint256_t>& point) {
    std::pair<uint256_t, uint256_t> r0 = point;
    std::pair<uint256_t, uint256_t> r1 = add(point, point);

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

std::pair<uint256_t, uint256_t> sign(uint256_t hashed, uint256_t private_key) {
    hashed = hashed % subgroup_order;
    std::cout << "PIZDEC TOTAL': " << (private_key > subgroup_order) << std::endl;
    // private_key = private_key % subgroup_order;
    // std::cout << "HASH % " << hashed.str(16, 64) << std::endl;

    uint256_t r = 0x0;
    uint256_t s = 0x0;
    while ((!r) || (!s)) {
        uint256_t k = safe_random(uint256_1, subgroup_order);
        std::cout << "rand_k: " << k.str(16, 64) << std::endl;
        std::pair<uint256_t, uint256_t> point = scalar_mult(k, base_point);
        r = point.first % subgroup_order;

        s = r.mulmod(private_key, subgroup_order);
        std::cout << "s1: " << s.str(16, 64) << std::endl;
        s = s.addmod(hashed, subgroup_order);
        std::cout << "s2: " << s.str(16, 64) << std::endl;
        std::cout << "rand_k: " << k.str(16, 64) << std::endl;
        std::cout << "PIZDEC: " << (k > subgroup_order) << std::endl;
        uint256_t temp = inverse_modulo(k, subgroup_order);
        std::cout << "temp " << temp.str(16, 64) << std::endl;
        s = s.mulmod(temp, subgroup_order);
        std::cout << "s3: " << s.str(16, 64) << std::endl;
        s = s % subgroup_order; // ((hashed + r * private_key) * inverse_modulo(k, subgroup_order)) % subgroup_order;
    }

    return std::make_pair(r, s);
}

bool verify(uint256_t hashed, 
            std::pair<uint256_t, uint256_t> siganture,
            std::pair<uint256_t, uint256_t> public_key) {
    
    uint256_t r = siganture.first, s = siganture.second;
    hashed = hashed % subgroup_order;
    
    uint256_t inv_s = inverse_modulo(s, subgroup_order);
    uint256_t u1 = inv_s.mulmod(hashed, subgroup_order);
    uint256_t u2 = inv_s.mulmod(r, subgroup_order);
    std::pair<uint256_t, uint256_t> mult_1 = scalar_mult(u1, base_point);
    std::pair<uint256_t, uint256_t> mult_2 = scalar_mult(u2, public_key);
    std::pair<uint256_t, uint256_t> point = add(mult_1, mult_2);

    return (r % subgroup_order) == (point.first % subgroup_order);
}



// int main() {
//     // uint256_t a = CAR_PUBLIC_KEY_FIRST, b = CAR_PUBLIC_KEY_SECOND;
//     // std::pair<uint256_t, uint256_t> p1 = std::make_pair(a, b);
//     // // std::cout << (*p1.first).str(16, 64) << '\n';
//     // // std::cout << (*p1.second).str(16, 64) << '\n';
//     // std::pair<uint256_t, uint256_t> p2 = std::make_pair(b, a);
//     // // std::pair<uint256_t, uint256_t> sss = add(p1, p2);
//     // std::pair<uint256_t, uint256_t> sss = scalar_mult(a, p1);
//     // std::cout << (sss.first).str(16, 64) << '\n';
//     // std::cout << (sss.second).str(16, 64) << '\n';


//     uint256_t person_private_key = uint256_t(PERSON_PRIVATE_KEY);
//     std::pair<uint256_t, uint256_t> car_public_key = std::make_pair(CAR_PUBLIC_KEY_FIRST, CAR_PUBLIC_KEY_SECOND);

//     uint256_t nonce = safe_random(uint256_1, uint256_max);
//     uint256_t hashed = hash_message(nonce);
//     std::cout << "HASH   " << hashed.str(16, 64) << '\n';

//     std::pair<uint256_t, uint256_t> signature = sign(hashed, person_private_key);
//     std::cout << "HELLO VASYA\n";
//     std::cout << "SIGNATURE\n";
//     std::cout << signature.first.str(16, 64) << '\n';
//     std::cout << signature.second.str(16, 64) << "\n\n";

//     bool result = verify(hashed, signature, car_public_key);
//     std::cout << "Result is..... " << result << "!!!!!\n";

//      // uint256_t a = car_public_key.first % subgroup_order;
//     // uint256_t inv = inverse_modulo(a, subgroup_order);
//     // std::cout << inv.str(16, 64) << '\n';
//     return 0;
// }