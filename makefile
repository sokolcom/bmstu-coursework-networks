CC = g++
CXXFLAGS = -std=c++11 #-Wall -Werror


SRC_UINT256 = $(wildcard uint256_t/*.cpp)
OBJ_UINT256 = $(patsubst %.cpp, %.o, $(wildcard $(SRC_UINT256)))

SRC_SHA256 = $(wildcard sha256/src/*.cpp)
OBJ_SHA256 = $(patsubst %.cpp, %.o, $(wildcard $(SRC_SHA256)))

CLIENT_SRC_CXX = $(wildcard src/person.cpp src/ec_dsa.cpp)
CLIENT_OBJ_SRC = $(patsubst %.cpp, %.o, $(wildcard $(CLIENT_SRC_CXX)))

SERVER_SRC_CXX = $(wildcard src/car.cpp src/ec_dsa.cpp)
SERVER_OBJ_SRC = $(patsubst %.cpp, %.o, $(wildcard $(SERVER_SRC_CXX)))


client.out: $(OBJ_UINT256) $(OBJ_SHA256) $(CLIENT_OBJ_SRC) 
	$(CC) -o $@ $^ $(LDFLAGS) $(CPPFLAGS) -lcrypto
$(CLIENT_OBJ_SRC):		CXXFLAGS += -lcrypto
$(OBJ_UINT256): CXXFLAGS += -fPIC
$(OBJ_SHA256):	CXXFLAGS += -fPIC

server.out: $(OBJ_UINT256) $(OBJ_SHA256) $(SERVER_OBJ_SRC) 
	$(CC) -o $@ $^ $(LDFLAGS) $(CPPFLAGS) -lcrypto
$(SERVER_OBJ_SRC):		CXXFLAGS += -lcrypto
$(OBJ_UINT256): CXXFLAGS += -fPIC
$(OBJ_SHA256):	CXXFLAGS += -fPIC

clean:
	$(RM) -rf *.out src/*.o uint256_t/*.o
