CC = gcc
CFLAGS1 = -Wall -g -c
CFLAGS2 = -g

all: file_enc_dec

file_enc_dec: file_enc_dec.o aes256.o
	${CC} ${CFLAGS2} -o $@ $^

file_enc_dec.o: file_enc_dec.c aes256.h
	${CC} ${CFLAGS1} -o $@ $<

aes256.o: aes256.c aes256.h
	${CC} ${CFLAGS1} -o $@ $<

clean:
	rm aes256.o file_enc_dec.o
