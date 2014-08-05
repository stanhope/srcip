CC		= gcc
CFLAGS		= -c -Wall $(FREEBSD) -O2
LDFLAGS		= -pthread
SOURCES		= srcip.c
OBJECTS		= $(SOURCES:.c=.o)
TARGET		= srcip

all: $(SOURCES) $(TARGET)

# FreeBSD, required that libJudy be compiled and available locally. Tested on 8.2Release.
freebsd: $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $(TARGET) /usr/lib/libpcap.a freebsd_libJudy.a

# Linux, linking with LIBCAP and JUDY statically
$(TARGET): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ /usr/lib/x86_64-linux-gnu/libpcap.a /usr/lib/libJudy.a

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJECTS) $(TARGET)
