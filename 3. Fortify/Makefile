hellomake:
	gcc vuln.c -std=c99 -m32 -fno-stack-protector -w -o  vuln.o -D_FORTIFY_SOURCE=2 -O1
	gcc vuln_2.c -o vuln_2.o -D_FORTIFY_SOURCE=2 -O1
	gcc vuln_3.c -o vuln_3.o -D_FORTIFY_SOURCE=2 -O1
clean:
	rm -f vuln.o vuln_2.o vuln_3.o

