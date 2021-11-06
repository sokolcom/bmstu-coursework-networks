CC = g++
CXXFLAGS = -O3 -std=c++11 #-Wall -Werror


SRC_UINT256 = $(wildcard uint256_t/*.cpp)
OBJ_UINT256 = $(patsubst %.cpp, %.o, $(wildcard $(SRC_UINT256)))

SRC_SHA256 = $(wildcard sha256/src/*.cpp)
OBJ_SHA256 = $(patsubst %.cpp, %.o, $(wildcard $(SRC_SHA256)))

CLIENT_SRC_CXX = $(wildcard src/person.cpp src/ec_dsa.cpp)
CLIENT_OBJ_SRC = $(patsubst %.cpp, %.o, $(wildcard $(CLIENT_SRC_CXX)))

SERVER_SRC_CXX = $(wildcard src/car.cpp src/ec_dsa.cpp)
SERVER_OBJ_SRC = $(patsubst %.cpp, %.o, $(wildcard $(SERVER_SRC_CXX)))


$(SERVER_OBJ_SRC):	CXXFLAGS += -lcrypto
$(CLIENT_OBJ_SRC):	CXXFLAGS += -lcrypto
$(OBJ_UINT256):		CXXFLAGS += -fPIC
$(OBJ_SHA256):		CXXFLAGS += -fPIC



server: server.out
	./$^

server_verbose: server.out
	./$^&

client: client.out
	./$^


server.out: $(OBJ_UINT256) $(OBJ_SHA256) $(SERVER_OBJ_SRC) 
	$(CC) -o $@ $^ $(LDFLAGS) $(CPPFLAGS) -lcrypto

client.out: $(OBJ_UINT256) $(OBJ_SHA256) $(CLIENT_OBJ_SRC) 
	$(CC) -o $@ $^ $(LDFLAGS) $(CPPFLAGS) -lcrypto



clean:
	$(RM) -rf *.out src/*.o uint256_t/*.o sha256/*.o
