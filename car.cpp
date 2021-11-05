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

#define PORT 8888
#define SERVER_IP "127.0.0.1"
#define MSG_LEN 1024
#define ROOT "/Users/vlad/Downloads/coursework-networks"
#define CAR_PRIVATE_KEY "0x2572c1e1fc6f2f517e6dffc867b8d6abc3c920b28eaf8a8ec7c33e38c58d04"

using namespace std;

std::set<std::string> user_tokens = { "666" };
std::set<std::string> user_sessions = {};

void perror_and_exit(std::string err_msg, size_t exit_code)
{
	perror(err_msg.c_str());
	exit(exit_code);
}

int accept_connection(int listener, struct sockaddr_in client_addr) {
	int sock;
	socklen_t cli_addr_size = sizeof(client_addr);
	std::cout << "here1" << std::endl;
	sock = accept(listener, (struct sockaddr*) &client_addr, &cli_addr_size);
	if(sock < 0) {
		std::cout << "here4334" << std::endl;
		perror_and_exit("accept()", 3);
	}
	std::cout << "here2" << std::endl;
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
		std::cout << "session exists" << std::endl;
		return true;
	}

	std::cout << "session not exists" << std::endl;
	return false;
}

bool is_chapter_correct(std::string auth_token, std::string chapter) {
	bool session_exists = is_session_exist(auth_token);
	if (chapter == "handshake" && !session_exists) {
		std::cout << "handhake chapter correct" << std::endl;
		return true;
	} else if (chapter == "response" && session_exists) {
		std::cout << "response chapter correct" << std::endl;
		return true;
	}
	
	std::cout << "chapter failed" << std::endl;
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
			std::cout << "here3 " << bytes_read << std::endl;
			printf("Recv failed");
			close(sock);
			is_executing = false;
			continue;
		}
		if (bytes_read == 0)
		{
			std::cout << "here4" << std::endl;
			puts("Client disconnected upexpectedly.");
			close(sock);
			accept_connection(listener, client_addr);
			continue ;
		}
		buf[bytes_read] = '\0';
		cout << "buf" << buf << "\n";
		char tst[MSG_LEN];
		strcpy(tst, buf);
		std::cout << "here5 " << buf <<std::endl;
		std::string message = std::string(buf);
		nlohmann::json js = nlohmann::json::parse(message);
		std::string user_token = js.at("auth_token");
		std::string chapter = js.at("chapter");
		std::cout << "car - " << user_token << " " << chapter << std::endl;
		if (!is_user_authorized(user_token)) {
			puts("Not authorized");
			close(sock);
			accept_connection(listener, client_addr);
			continue;
		}

		if (!is_chapter_correct(user_token, chapter)) {
			puts("Invalid chapter");
			std::cout << chapter << std::endl;
			close(sock);
			accept_connection(listener, client_addr);
			continue;
		}

		if (chapter == "handshake") {
			std::cout << "handshake handling" << std::endl;
			user_sessions.insert(user_token);
			std::string nonce = safe_random(uint256_1, uint256_max).str(16, 64);
			std::string nonce_hash = hash_message(nonce).str(16, 64);
			std::pair<uint256_t, uint256_t> signature = sign(nonce_hash, uint256_t(CAR_PRIVATE_KEY));
			std::string r = signature.first.str(16,64);
			std::string s = "{"
							"\"nonce\": \"" + nonce_hash + "\","
							"\"signature\": {"
								"\"r\": \"\"," 
								"\"s\": \"\""
							  "}"
							"}";
			send(sock, s.c_str(), s.size(), 0);
		} else if (chapter == "response") {
			std::cout << "response handling" << std::endl;
			std::cout << "car opened" << std::endl;
			for(auto it = user_sessions.begin(); it != user_sessions.end(); ) {
				if(*it == user_token) {
					it = user_sessions.erase(it);
					break;
				} else {
					++it;
				}
    		}

			std::string nonce = js.at("nonce");
			std::string hash = js.at("hash");
			std::string success = "true";
			std::string s = "{ \"success\": " + success + " }";
			std::cout << s << std::endl;
			send(sock, s.c_str(), s.size(), 0);

			puts("Succesfully finished");
			close(sock);
			accept_connection(listener, client_addr);
			continue;

		} else {
			puts("Invalid chapter");
			close(sock);
			accept_connection(listener, client_addr);
			continue;
		}
	}
	close(listener);
	return 0;
}