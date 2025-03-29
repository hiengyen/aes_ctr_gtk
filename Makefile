TARGET = aes_ctr_gtk

SOURCES = aes_ctr_gtk.c aes.c

CC = gcc

CFLAGS = `pkg-config --cflags --libs gtk+-3.0`


all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) -o $(TARGET) $(SOURCES) $(CFLAGS) 

clean:
	rm -f $(TARGET) encrypted.bin decrypted.txt

.PHONY: all clean
