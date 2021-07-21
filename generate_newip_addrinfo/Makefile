CC=gcc
OB=generate
BIN_FLODER=bin/
FLAGS=-o
BIN_PATH=$(BIN_FLODER)$(OB)
NIP = include/nipaddr_output

all: $(OB).c 
	$(CC) $(FLAGS) $(BIN_PATH) $(OB).c $(NIP).c

run: $(BIN_PATH)
	./$(BIN_PATH)

clean:
	rm -rf $(BIN_PATH)