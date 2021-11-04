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

#define PORT 8888
#define SERVER_IP "127.0.0.1"
#define MSG_LEN 1024
#define ROOT "/Users/vlad/Downloads/coursework-networks"

using namespace std;

void perror_and_exit(std::string err_msg, size_t exit_code)
{
	perror(err_msg.c_str());
	exit(exit_code);
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
	//ThreadPool tp;
	while(1)
	{

		int sock;
		int bytes_read;
		char *buf = (char*)malloc(MSG_LEN);
		socklen_t cli_addr_size = sizeof(client_addr);

		sock = accept(listener, (struct sockaddr*) &client_addr, &cli_addr_size);
		if(sock < 0)
			perror_and_exit("accept()", 3);

		bytes_read = recv(sock, buf, MSG_LEN, 0);
		if (bytes_read < 0)
		{
			printf("Recv failed");
			close(sock);
			continue ;
		}
		if (bytes_read == 0)
		{
			puts("Client disconnected upexpectedly.");
			close(sock);
			continue ;
		}
		buf[bytes_read] = '\0';
		cout << "buf" << buf << "\n";
		char tst[MSG_LEN];
		strcpy(tst, buf);

		std::string s = "{ \"random_number\": \"fook\", \"hash\": \"s123435422423423\"}";
		send(sock, s.c_str(), s.size(), 0);
		//tp.queueWork(sock, tst);

		free(buf);
	}
	close(listener);
	return 0;
}