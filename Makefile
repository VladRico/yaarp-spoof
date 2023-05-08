CC=gcc
CFLAGS= -g -Wall -lpcap -lpthread -ftrivial-auto-var-init=pattern
TARGET=yaarp-spoof

all: $(TARGET) 

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c
	

clean:
		$(RM) $(TARGET)

