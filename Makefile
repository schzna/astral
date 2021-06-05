CC=gcc -static -std=c11

all : test astral astral.c x86.h

test : astral
	./astral
	rm astral

astral : astral.c
	$(CC) -o astral astral.c