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

#define PORT 8888
#define MSG_LEN 1024
#define ERROR 1
#define PERSON_PRIVATE_KEY "0x631ee57d7cb6801890415ccc4622a12ddc0d0025ef087ce0e2798941473d142"
#define CAR_PUBLIC_KEY_FIRST "0x7630498e5e4df030aedb1b0ea44ee1ce2a323427aaf2a959d9d31e39da843361"
#define CAR_PUBLIC_KEY_SECOND "0x51859ccdf5567141f640eeefae2eddc4e1b1696149d8564a9a4ae7f756f32dc7"

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

	//printf("enter your Name: \n");
	//cin >> userName;

	//char message[MSG_LEN];
	//printf("enter url: \n");
	//scanf("%s", message);

	//string mes = generateGetMessage(message);
	//const char * msg = mes.c_str();

	//printf("Sending message...\n\n");

	//cout << "msg " << msg << "\n";
    char message[MSG_LEN];
    const char *msg_string = "sdsds";//std::string("sdsdsd").c_str();
	sendto(person_socket, msg_string, strlen(msg_string), 0, (struct sockaddr*) &server_addr, sizeof(server_addr));

	unsigned int server_addr_len = sizeof(server_addr);
	if (recvfrom(person_socket, message, MSG_LEN, 0, (struct sockaddr*) &server_addr, &server_addr_len) == -1) {
        return ERROR;
    }

    std::string handshake_response_msg = std::string(message); 
    nlohmann::json js = handshake_response_msg;
    // decode handshake response 

	close(person_socket);
	return 0;
}