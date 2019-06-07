CC = gcc
SRC = Src\Crypter
BIN = .
OBJ = Obj
CFLAGS = -std=c99 -c -Wall -pedantic -O2 -m32

CONTAINER32 = Src\Container\32
CONTAINER64 = Src\Container\64
GENERATED_ASM = $(CONTAINER32)\decryption_payload.asm $(CONTAINER32)\image_base.inc\
	$(CONTAINER32)\image_size.ing $(CONTAINER32)\infile_array.inc $(CONTAINER32)\infile_size.inc\
	$(CONTAINER32)\key_size.inc $(CONTAINER32)\logfile_select.asm\
	$(CONTAINER64)\decryption_payload.asm $(CONTAINER64)\image_base.inc\
	$(CONTAINER64)\image_size.ing $(CONTAINER64)\infile_array.inc $(CONTAINER64)\infile_size.inc\
	$(CONTAINER64)\key_size.inc $(CONTAINER64)\logfile_select.asm

.PHONY:all
all: verbose.o fileaccess.o hyperion.o pe_general.o pe32.o pe64.o fasmoutput.o \
	encryption.o secure_string.o aes.o
	$(CC) -o $(BIN)\hyperion.exe $(OBJ)\hyperion.o $(OBJ)\verbose.o \
	$(OBJ)\fileaccess.o $(OBJ)\pe_general.o $(OBJ)\pe32.o $(OBJ)\pe64.o \
	$(OBJ)\fasmoutput.o $(OBJ)\encryption.o $(OBJ)\secure_string.o $(OBJ)\aes.o

hyperion.o: $(SRC)\hyperion.c
	$(CC) $(CFLAGS) -o $(OBJ)\hyperion.o $(SRC)\hyperion.c

verbose.o: $(SRC)\verbose.c
	$(CC) $(CFLAGS) -o $(OBJ)\verbose.o $(SRC)\verbose.c

secure_string.o: $(SRC)\secure_string.c
	$(CC) $(CFLAGS) -o $(OBJ)\secure_string.o $(SRC)\secure_string.c

fileaccess.o: $(SRC)\fileaccess.c
	$(CC) $(CFLAGS) -o $(OBJ)\fileaccess.o $(SRC)\fileaccess.c

pe_general.o: $(SRC)\pe_general.c
	$(CC) $(CFLAGS) -o $(OBJ)\pe_general.o $(SRC)\pe_general.c

pe32.o: $(SRC)\pe32.c
	$(CC) $(CFLAGS) -o $(OBJ)\pe32.o $(SRC)\pe32.c

pe64.o: $(SRC)\pe64.c
	$(CC) $(CFLAGS) -o $(OBJ)\pe64.o $(SRC)\pe64.c

fasmoutput.o: $(SRC)\fasmoutput.c
	$(CC) $(CFLAGS) -Wno-format -o $(OBJ)\fasmoutput.o $(SRC)\fasmoutput.c

encryption.o: $(SRC)\encryption.c
	$(CC) $(CFLAGS) -o $(OBJ)\encryption.o $(SRC)\encryption.c

aes.o: $(SRC)\aes.c
	$(CC) $(CFLAGS) -o $(OBJ)\aes.o $(SRC)\aes.c

.PHONY:clean
clean:
	del $(BIN)\hyperion.exe $(OBJ)\*.o $(GENERATED_ASM) >nul 2>&1
