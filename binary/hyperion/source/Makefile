CC = gcc
CFLAGS = -std=c99 -Wall -pedantic -O2 -m32
SRC = $(wildcard Src/Crypter/*.c)
OBJ = $(SRC:.c=.o)
EXECUTABLE=hyperion.exe
 
all: hyperion
 
hyperion: $(OBJ)
	$(CC) $(CFLAGS) -o $(EXECUTABLE) $^
 
.PHONY:clean
clean:
	del Src\Crypter\*.o $(EXECUTABLE)
