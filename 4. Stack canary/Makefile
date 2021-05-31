CC = gcc
CFLAGS = -std=c99 -m32 -w

hellomake:
	${CC} vuln.c ${CFLAGS} -no-pie  -fno-stack-protector -z execstack  -o vuln.o
	${CC} vuln.c ${CFLAGS} -no-pie -fno-stack-protector  -o vuln_p.o
	${CC} vuln_2.c ${CFLAGS} -z execstack -fstack-protector-all -o vuln_2.o
clean:
	rm -f vuln.o vuln_p.o vuln_2.o vuln_2_p.o
