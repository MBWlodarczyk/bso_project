CC = gcc
CFLAGS = -std=c99 -no-pie -m32 -w


hellomake:
	${CC} vuln.c ${CFLAGS} -o vuln.o
	${CC} vuln.c ${CFLAGS}  -z relro -z now -o vuln_p.o
clean:
	rm -f vuln.o vuln_p.o
