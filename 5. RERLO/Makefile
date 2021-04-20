hellomake:
	gcc vuln.c -std=c99 -no-pie -m32 -w -o vuln.o
	gcc vuln.c -std=c99 -no-pie -m32 -w  -z relro -z now -o vuln_p.o



clean:
	rm -f vuln.o vuln_p.o
