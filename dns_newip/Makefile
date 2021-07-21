CC=gcc
OB=newip_dns
BIN_FLODER=bin/
FLAGS=-o
BIN_PATH=$(BIN_FLODER)$(OB)

all: $(OB).c
	$(CC) $(FLAGS) $(BIN_PATH) $(OB).c

run: $(BIN_PATH)
	./$(BIN_PATH)

clean:
	rm -rf $(BIN_PATH)