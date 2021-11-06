#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <iostream>
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <string>
#include <nlohmann/json.hpp>
#include <set>
#include "../include/ec_dsa.h"
#include "../include/define.h"

#define PORT 8888
#define SERVER_IP "127.0.0.1"
#define MSG_LEN 2048

//55406959067906966216185922075165173647310218242524135206265003447211541460366

// #define ROOT "/Users/vlad/Downloads/coursework-networks"
#define CAR_PRIVATE_KEY "0x2572c1e1fc6f2f517e6dffc867b8d6abc3c920b28eaf8a8ec7c33e38c58d04"
#define CAR_PUBLIC_KEY_FIRST "0x5085c9e4f84d48d3d1f93e2c8511994c572b3a5baabe5834e0093f971aa0f891"
#define CAR_PUBLIC_KEY_SECOND "0x66cba7d26a1ee0b05541193967470a4d5b5bce4e643c41af98d38698096bba43"

#define PERSON_PUBLIC_KEY_FIRST "0x7630498e5e4df030aedb1b0ea44ee1ce2a323427aaf2a959d9d31e39da843361"
#define PERSON_PUBLIC_KEY_SECOND "0x51859ccdf5567141f640eeefae2eddc4e1b1696149d8564a9a4ae7f756f32dc7"


using namespace std;

std::set<std::string> user_tokens = { "777" };
std::set<std::string> user_sessions = {};

void perror_and_exit(std::string err_msg, size_t exit_code)
{
	perror(err_msg.c_str());
	exit(exit_code);
}

int accept_connection(int listener, struct sockaddr_in client_addr) {
	int sock;
	socklen_t cli_addr_size = sizeof(client_addr);
	// std::cout << "here1" << std::endl;
	sock = accept(listener, (struct sockaddr*) &client_addr, &cli_addr_size);
	if(sock < 0) {
		// std::cout << "here4334" << std::endl;
		perror_and_exit("accept()", 3);
	}
	// std::cout << "here2" << std::endl;
	return sock;
}

bool is_user_authorized(std::string auth_token) {
	auto search = user_tokens.find(auth_token);

	if (search != user_tokens.end()) {
		return true; 
	}

	return false;
}

bool is_session_exist(std::string auth_token) {
	auto search = user_sessions.find(auth_token);

	if (search != user_sessions.end()) {
		std::cout << "SERVER: session exists" << std::endl;
		return true;
	}

	std::cout << "SERVER: session not exists" << std::endl;
	return false;
}

bool is_stage_correct(std::string auth_token, std::string stage) {
	bool session_exists = is_session_exist(auth_token);
	if (stage == "handshake" && !session_exists) {
		std::cout << "SERVER: handhake stage correct" << std::endl;
		return true;
	} else if (stage == "response" && session_exists) {
		std::cout << "SERVER: response stage correct" << std::endl;
		return true;
	}
	
	std::cout << "SERVER: stage failed" << std::endl;
	return false;
}

int main()
{
	struct sockaddr_in addr, client_addr;

	int listener = socket(AF_INET, SOCK_STREAM, 0);
	if(listener < 0)
		perror_and_exit("socket()", 1);

	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (::bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror_and_exit("bind()", 2);
	}

	listen(listener, 10);
	printf("Server is listening on %s:%d...\n", SERVER_IP, PORT);
	
	int sock = accept_connection(listener, client_addr);
	bool is_executing = true;

	while(is_executing)
	{
		int bytes_read;
		char *buf = (char*)malloc(MSG_LEN);
		bytes_read = recv(sock, buf, MSG_LEN, 0);
		if (bytes_read < 0)
		{
			// std::cout << "here3 " << bytes_read << std::endl;
			printf("SERVER: Recv failed");
			close(sock);
			is_executing = false;
			continue;
		}
		if (bytes_read == 0)
		{
			// std::cout << "here4" << std::endl;
			puts("SERVER: Client disconnected upexpectedly.");
			close(sock);
			accept_connection(listener, client_addr);
			continue ;
		}
		buf[bytes_read] = '\0';
		// cout << "buf" << buf << "\n";
		char tst[MSG_LEN];
		strcpy(tst, buf);
		std::string message = std::string(buf);
		nlohmann::json js = nlohmann::json::parse(message);
		std::string user_token = js.at("auth_token");
		std::string stage = js.at("stage");
	
		if (!is_user_authorized(user_token)) {
			puts("SERVER: Not authorized");
			close(sock);
			accept_connection(listener, client_addr);
			continue;
		}

		if (!is_stage_correct(user_token, stage)) {
			puts("SERVER: Invalid stage");
			std::cout << stage << std::endl;
			close(sock);
			accept_connection(listener, client_addr);
			continue;
		}

		if (stage == "handshake") {
			std::cout << "SERVER: handshake handling" << std::endl;
			user_sessions.insert(user_token);
			uint256_t nonce = safe_random(uint256_1, uint256_max);
			std::string nonce_message = nonce.str(16,64);
			uint256_t nonce_hash = hash_message(nonce);
			// std::cout << "SERVER nonce_hash - " << nonce_hash.str(16, 64) << std::endl;
			std::pair<uint256_t, uint256_t> signature = sign(nonce_hash, uint256_t(CAR_PRIVATE_KEY));
			std::string r = signature.first.str(16,64);
			std::string s = signature.second.str(16,64);
			// std::cout << "SERVER nonce(10th) - " << nonce_message << std::endl;
			// std::cout << "SERVER R - " << r << std::endl;
			// std::cout << "SERVER S - " << s << std::endl;

			nlohmann::json js_norm = {
				{"nonce", nonce_message},
				{"signature", {
					{"r", r},
					{"s", s}
				}}
			};
			std::string m = js_norm.dump();
			//bool is_verified = verify(nonce_hash, make_pair(signature.first, signature.second), make_pair(uint256_t(CAR_PUBLIC_KEY_FIRST), uint256_t(CAR_PUBLIC_KEY_SECOND)));
			//std::cout << "HUYNYA - " << is_verified << std::endl;
			send(sock, m.c_str(), m.size(), 0);
		} else if (stage == "response") {
			std::cout << "SERVER: response handling" << std::endl;
			for(auto it = user_sessions.begin(); it != user_sessions.end(); ) {
				if(*it == user_token) {
					it = user_sessions.erase(it);
					break;
				} else {
					++it;
				}
    		}

			std::string nonce = js.at("nonce");
			std::string r = js.at("signature").at("r");
			std::string s = js.at("signature").at("s");

			uint256_t nonce_number = uint256_t(nonce);

			uint256_t r_number = uint256_t(r);
			uint256_t s_number = uint256_t(s);

			pair<uint256_t, uint256_t> person_public_key = make_pair(PERSON_PUBLIC_KEY_FIRST, PERSON_PUBLIC_KEY_SECOND);
			
			bool is_verified = verify(hash_message(nonce_number), make_pair(r_number, s_number), person_public_key);

			std::string result;
			if (is_verified) {
				std::cout << "SERVER: Verified! Car opened" << std::endl;
				result = "true";
			} else {
				puts("SERVER: Not verified Response, car closed!");
				result = "false";
			}

			s = "{ \"success\": " + result + " }";
			std::cout << s << std::endl;
			send(sock, s.c_str(), s.size(), 0);

			close(sock);
			accept_connection(listener, client_addr);
			continue;
		} else {
			puts("SERVER: Invalid stage");
			close(sock);
			accept_connection(listener, client_addr);
			continue;
		}
	}
	close(listener);
	return 0;
}