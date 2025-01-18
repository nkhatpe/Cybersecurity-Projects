CC = gcc
CFLAGS = -Wall -Wextra

all: vuln_program generate_attack

vuln_program: vuln_program.c
	$(CC) $(CFLAGS) -fno-stack-protector -z execstack -static -o vuln_program vuln_program.c

generate_attack: exploit.c
	$(CC) $(CFLAGS) -o exploit exploit.c

clean:
	rm -f vuln_program exploit

