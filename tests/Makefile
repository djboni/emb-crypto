CC = gcc
CFLAGS = -Wall -Wextra -std=c90 -pedantic
INC = -I../include

all: aes.o keccak.o keccak_hash.o keccak_prng.o keccak_secret.o

keccak_%.o: ../source/keccak_%.c ../include/keccak_%.h ../include/keccak.h
	$(CC) $(CFLAGS) $(INC) -c $<

%.o: ../source/%.c ../include/%.h
	$(CC) $(CFLAGS) $(INC) -c $<

clean:
	rm -f *.o *.so *_.c *.gcda *.gcno

