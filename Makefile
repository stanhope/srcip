CC		= gcc
CFLAGS		= -c -Wall
LDFLAGS		= -pthread
SOURCES		= srcip.c
OBJECTS		= $(SOURCES:.c=.o)
TARGET		= srcip

all: $(SOURCES) $(TARGET)

#$(TARGET): $(OBJECTS) 
#	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ -lpcap -lJudy

$(TARGET): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ /usr/lib/x86_64-linux-gnu/libpcap.a /usr/lib/libJudy.a

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJECTS) $(TARGET)
