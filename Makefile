CC = gcc
CFLAGS = -Wall -Wextra

TARGET = firewall
SRC = firewall-ids.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)
