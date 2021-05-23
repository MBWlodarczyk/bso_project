CC = gcc
CFLAGS = -std=c99 -m32 -fno-stack-protector -w

hellomake:
	${CC} vuln.c ${CFLAGS} -no-pie -o vuln.o
	${CC} vuln.c ${CFLAGS} -o vuln_p.o
	${CC} vuln_2.c ${CFLAGS} -no-pie -static  -o vuln_2.o
clean:
	rm -f vuln.o vuln_p.o vuln_2.o
