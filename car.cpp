#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#define PORT 8888
#define ERROR 1
#define 

int main() {
    int carSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    if (carSocket < 0) {
        return ERROR;
    }

    struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (connect(carSocket, (struct sockaddr*) &serverAddr, sizeof(serverAddr)) < 0) {
        return ERROR;
    }

	printf("enter your Name: \n");
	cin >> userName;

	char message[MSG_LEN];
	printf("enter url: \n");
	scanf("%s", message);

	string mes = generateGetMessage(message);
	const char * msg = mes.c_str();

	printf("Sending message...\n\n");

	cout << "msg " << msg << "\n";
	sendto(clientSock, msg, strlen(msg), 0, (struct sockaddr*) &serverAddr, sizeof(serverAddr));

	unsigned int sAddrlen = sizeof(serverAddr);
	if (recvfrom(clientSock, message, MSG_LEN, 0, (struct sockaddr*) &serverAddr, &sAddrlen) == -1)
		perror_and_exit("recvfrom", 1);
	std::cout << message;

	close(clientSock);
	return 0;
}