CC = gcc
CFLAGS = -std=c99 -no-pie -m32 -fno-stack-protector -w

hellomake:
	${CC} vuln.c ${CFLAGS} -z execstack -o vuln.o
	${CC} vuln.c ${CFLAGS} -o vuln_p.o
	${CC} vuln_2.c ${CFLAGS} -z execstack  -o vuln_2.o
	${CC} vuln_2.c ${CFLAGS} -o vuln_2_p.o

clean:
	rm -f vuln.o vuln_p.o vuln_2.o vuln_2_p.o
