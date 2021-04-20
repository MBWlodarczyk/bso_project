hellomake:
	gcc vuln.c -std=c99 -no-pie -m32 -fno-stack-protector -z execstack -w -o vuln.o
	gcc vuln.c -std=c99 -no-pie -m32 -fno-stack-protector -w -o vuln_p.o
	gcc vuln_2.c -std=c99 -m32 -fno-stack-protector -z execstack -w -o vuln_2.o
	gcc vuln_2.c -std=c99 -m32 -fno-stack-protector -w -o vuln_2_p.o

clean:
	rm -f vuln.o vuln_p.o vuln_2.o vuln_2_p.o
