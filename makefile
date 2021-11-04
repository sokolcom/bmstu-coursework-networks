CC = g++
CXXFLAGS = -std=c++11 #-Wall -Werror


SRC_UINT256 = $(wildcard uint256_t/*.cpp)
OBJ_UINT256 = $(patsubst %.cpp, %.o, $(wildcard $(SRC_UINT256)))

SRC_SHA256 = $(wildcard sha256/src/*.cpp)
OBJ_SHA256 = $(patsubst %.cpp, %.o, $(wildcard $(SRC_SHA256)))

SRC_CXX = $(wildcard src/*.cpp)
OBJ_SRC = $(patsubst %.cpp, %.o, $(wildcard $(SRC_CXX)))



app.out: $(OBJ_UINT256) $(OBJ_SHA256) $(OBJ_SRC) 
	$(CC) -o $@ $^ -lcrypto

$(OBJ_SRC):		CXXFLAGS += -lcrypto
$(OBJ_UINT256): CXXFLAGS += -fPIC
$(OBJ_SHA256):	CXXFLAGS += -fPIC



clean:
	$(RM) -rf *.out src/*.o uint256_t/*.o
