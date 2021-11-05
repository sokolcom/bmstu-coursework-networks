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


// #define PERSON_PRIVATE_KEY "0x631ee57d7cb6801890415ccc4622a12ddc0d0025ef087ce0e2798941473d142"
// #define CAR_PUBLIC_KEY_FIRST "0x7630498e5e4df030aedb1b0ea44ee1ce2a323427aaf2a959d9d31e39da843361"
// #define CAR_PUBLIC_KEY_SECOND "0x51859ccdf5567141f640eeefae2eddc4e1b1696149d8564a9a4ae7f756f32dc7"


const uint256_t field_modulo = FIELD_MODULO;
const uint256_t subgroup_order = SUBGROUP_ORDER;
std::pair<uint256_t, uint256_t> base_point = std::make_pair(BASE_POINT_X, BASE_POINT_Y);


uint256_t safe_random(const uint256_t a, const uint256_t b) {
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

uint256_t hash_message(const std::string& message) {
	SHA256 sha;
	sha.update(message);
    return uint256_t(SHA256::toString(sha.digest()));
}

static uint256_t inverse_modulo(const uint256_t& x, const uint256_t& modulo) {
    // Fermat's little theorem
    return x.powmod(modulo - 2, modulo);
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

std::pair<uint256_t, uint256_t> sign(std::string& message, uint256_t private_key) {
    uint256_t hashed = hash_message(message) % subgroup_order;
    uint256_t r = 0x0;
    uint256_t s = 0x0;
    while ((!r) || (!s)) {
        uint256_t k = safe_random(uint256_1, subgroup_order);
        std::pair<uint256_t, uint256_t> point = scalar_mult(k, base_point);
        r = point.first % subgroup_order;

        s = r.mulmod(private_key, subgroup_order);
        s = s.addmod(hashed, subgroup_order);
        uint256_t temp = inverse_modulo(k, subgroup_order);
        s = s.mulmod(temp, subgroup_order);
        s = s % subgroup_order; // ((hashed + r * private_key) * inverse_modulo(k, subgroup_order)) % subgroup_order;
    }

    return std::make_pair(r, s);
}

bool verify(std::string& message, 
            std::pair<uint256_t, uint256_t> siganture,
            std::pair<uint256_t, uint256_t> public_key) {
    
    uint256_t r = siganture.first, s = siganture.second;
    uint256_t hashed = hash_message(message) % subgroup_order;
    
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

//     // uint256_t nonce = safe_random(uint256_1, uint256_max);
//     // std::string message = nonce.str(16, 64);
//     std::string message = "0x8f534c4449b93615f0f249ac06d7bc25efc4481b536b1d812d557b072713e5de";
//     std::cout << message << '\n';

//     std::pair<uint256_t, uint256_t> signature = sign(message, person_private_key);
//     std::cout << "HELLO VASYA\n";
//     std::cout << "SIGNATURE\n";

//     // uint256_t a = person_private_key % subgroup_order;
//     // uint256_t inv = inverse_modulo(a, subgroup_order);
//     // std::cout << inv.str(16, 64) << '\n';


//     std::cout << signature.first.str(16, 64) << '\n';
//     std::cout << signature.second.str(16, 64) << "\n\n";
//     // std::string x = "0x3b4a2a4b70469efb625f7ad50abdf25a784690740c6ad49e75699981c8e79b9", y = "0xfb6f0e2c71bd2fcb7f756e9f6300a553522ed706ffe6c34d087090543ddd452";
//     // std::string x = "0xcaf1369c602bcc0bf4489b18b459dc29e375faf50c51f28b16b952881b12743", y = "0x1c7aa2259d7b3a31b4ee92a6ef08bd0a9701f8fb0d9a6970a894f834c163323";
//     // uint256_t xx = x, yy = y;
//     // std::pair<uint256_t, uint256_t> signature = std::make_pair(x, y);

//     bool result = verify(message, signature, car_public_key);
//     std::cout << "Result is..... " << result << "!!!!!\n";

//     return 0;
// }