CC=gcc
OB=dns_newip
BIN_FLODER=bin/
FLAGS=-o
BIN_PATH=$(BIN_FLODER)$(OB)
INCLUDE=dns_transtable.c dns_struct.c dns_table.c

all: $(OB).c
	$(CC) $(FLAGS) $(BIN_PATH) $(OB).c $(INCLUDE)

run: $(BIN_PATH)
	sudo ./$(BIN_PATH) 10.3.9.44 ./bin/dns_data.txt

clean:
	rm -rf $(BIN_PATH)