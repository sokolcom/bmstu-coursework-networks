#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <string>
#include "../uint256_t/uint256_t.h"
#include <utility>
#include <nlohmann/json.hpp>
#include <openssl/rand.h>
#include <iostream>
#include "../include/ec_dsa.h"

#define PORT 8888
#define MSG_LEN 1024
#define ERROR 1
#define PERSON_PRIVATE_KEY "0x631ee57d7cb6801890415ccc4622a12ddc0d0025ef087ce0e2798941473d142"
#define CAR_PUBLIC_KEY_FIRST "0x7630498e5e4df030aedb1b0ea44ee1ce2a323427aaf2a959d9d31e39da843361"
#define CAR_PUBLIC_KEY_SECOND "0x51859ccdf5567141f640eeefae2eddc4e1b1696149d8564a9a4ae7f756f32dc7"
#define USER_TOKEN "666"

using namespace std;

int main() {
    uint256_t person_private_key = uint256_t(PERSON_PRIVATE_KEY);
    pair<uint256_t, uint256_t> car_public_key = make_pair(CAR_PUBLIC_KEY_FIRST, CAR_PUBLIC_KEY_SECOND);

    int person_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    if (person_socket < 0) {
        return ERROR;
    }

    struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);
	server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (connect(person_socket, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0) {
        return ERROR;
    }

    char message[MSG_LEN];
	std::string handshake_message = "{\"auth_token\": \"" + std::string(USER_TOKEN) + "\", \"chapter\": \"handshake\"}";
    const char *handhake_c_string = handshake_message.c_str();
	sendto(person_socket, handhake_c_string, strlen(handhake_c_string), 0, (struct sockaddr*) &server_addr, sizeof(server_addr));

	unsigned int server_addr_len = sizeof(server_addr);
	if (recvfrom(person_socket, message, MSG_LEN, 0, (struct sockaddr*) &server_addr, &server_addr_len) == -1) {
        return ERROR;
    }

    std::string handshake_response_msg = std::string(message); 
    auto js = nlohmann::json::parse(handshake_response_msg);
	std::string nonce = js.at("nonce");
	std::string r = js.at("signature").at("r");
	std::string s = js.at("signature").at("s");
	std::cout << "CLIENT: person received challenge: " << nonce << " " << r << " " << s << std::endl;
	std::cout << handshake_response_msg;

	uint256_t nonce_hash = hash_message(nonce);
	uint256_t r_number = uint256_t(r);
	uint256_t s_number = uint256_t(s);

	bool is_verified = verify(nonce_hash, make_pair(r_number, s_number), car_public_key);

	if (!is_verified) {
		std::cout << "CLIENT: Challenge not verified" << std::endl;
		close(person_socket);
		return ERROR;
	}

	std::pair<uint256_t, uint256_t> person_signature = sign(nonce_hash, uint256_t(PERSON_PRIVATE_KEY));
	
    // decode handshake response

	char new_message[MSG_LEN];

	std::string response_message = "{"
									"\"auth_token\": \"" + std::string(USER_TOKEN) + "\","
									"\"chapter\": \"response\","
									"\"nonce\": \"" + nonce + "\","
									"\"signature\": {"
										"\"r\": \"" + person_signature.first.str(16,64) + "\"," 
								  		"\"s\": \"" + person_signature.second.str(16,64) + "\""
							  			"} "
									"}";
    const char *response_c_string = response_message.c_str();
	sendto(person_socket, response_c_string, strlen(response_c_string), 0, (struct sockaddr*) &server_addr, sizeof(server_addr));
	if (recvfrom(person_socket, new_message, MSG_LEN, 0, (struct sockaddr*) &server_addr, &server_addr_len) == -1) {
        return ERROR;
    }
	std::cout <<  std::string(new_message) << std::endl;
	std::string response_response_msg = std::string(new_message);
	auto js_response = nlohmann::json::parse(response_response_msg);
	std::cout << js_response << std::endl;

	bool success = js_response.at("success");
	if (success) {
		std::cout << "CLIENT: car opened!" << std::endl;
	} else {
		std::cout << "CLIENT: car not opened!" << std::endl;
	}

	close(person_socket);
	return 0;
}