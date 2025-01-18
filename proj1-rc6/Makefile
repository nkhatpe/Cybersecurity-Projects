CC = gcc
CFLAGS = -Wall -Wextra -std=c99
SRC = rc6.c
OBJ = $(SRC:.c=.o)
EXEC = rc6_custom

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lm

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(EXEC) $(OBJ)

