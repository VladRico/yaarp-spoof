CC=clang
CFLAGS= -g -Wall -std=c2x -pedantic -lpcap -lpthread -ftrivial-auto-var-init=pattern -D_DEFAULT_SOURCE
TARGET=yaarp-spoof

all: $(TARGET) 

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c
	

static: $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c -static -DSTATICPCAP

clean:
		$(RM) $(TARGET)

