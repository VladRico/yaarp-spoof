CC=gcc
CFLAGS= -g -Wall -lpcap
TARGET=arp-spoof

all: $(TARGET) 

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c
	

clean:
		$(RM) $(TARGET)

