CC = gcc
CFLAGS = -Wall -Wextra -std=c90 -pedantic
INC = -I../include

all: aes.o

aes.o: ../source/aes.c ../include/aes.h
	$(CC) $(CFLAGS) $(INC) -c $<

clean:
	rm -f *.o *.so *_.c

