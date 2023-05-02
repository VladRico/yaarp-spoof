CC=gcc
CFLAGS= -g -Wall -lpcap -lpthread
TARGET=yaarp-spoof

all: $(TARGET) 

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c
	

clean:
		$(RM) $(TARGET)

