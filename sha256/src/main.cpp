#include <iostream>
#include <chrono>
#include <ctime>
#include <utility>
// #include "SHA256.h"

int main(int argc, char ** argv) {

	int a = 0;
	int b = 2;
	std::pair<int*, int*> c = std::make_pair(&a, &b);

	if (!c.first) {
		std::cout << "YES!\n";
	} else {
		std::cout << "NO!\n";
	}

	// for(int i = 1 ; i < argc ; i++) {
	// 	SHA256 sha;
	// 	sha.update(argv[i]);
	// 	uint8_t * digest = sha.digest();

	// 	std::cout << SHA256::toString(digest) << std::endl;

	// 	delete[] digest;
	// }

	return EXIT_SUCCESS;
}
