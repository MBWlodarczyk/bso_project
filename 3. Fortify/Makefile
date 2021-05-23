CC = gcc
CFLAGS = -O1 -D_FORTIFY_SOURCE=2


hellomake:
	${CC} vuln.c -std=c99 -m32 -fno-stack-protector -w -o  vuln.o ${CFLAGS}
	${CC} vuln_2.c -o vuln_2.o ${CFLAGS}
	${CC} vuln_3.c -o vuln_3.o ${CFLAGS}
	${CC} vuln_4.c -o vuln_4.o  -std=c99 -no-pie -static -m32 -fno-stack-protector -w -z execstack
clean:
	rm -f vuln.o vuln_2.o vuln_3.o vuln_4.o

