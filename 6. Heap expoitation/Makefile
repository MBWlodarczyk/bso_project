CC=gcc
CFLAGS=-m32 -std=c99 -fno-stack-protector -no-pie -w -O0

Hellomake:
	$(CC) vuln.c $(CFLAGS) -o vuln.o
	$(CC) vuln_2.c $(CFLAGS) -o vuln_2.o
	$(CC) vuln_3.c $(CFLAGS) -o vuln_3.o