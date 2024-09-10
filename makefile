CC = gcc
CXXFLAGS = -Wall -std=c++14 -D_GNU_SOURCE
LDFLAGS = -lncurses -lpcap -lstdc++ -lpthread

all: example

example: main.o display.o capture.o
	$(CC) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

main.o: src/capture.h src/display.h
	$(CC) $(CFLAGS) -c src/main.cpp

display.o: src/display.h
	$(CC) $(CXXFLAGS) -c src/display.cpp

capture.o: src/capture.h
	$(CC) $(CXXFLAGS) -c src/capture.cpp

clean:
	rm -f example *.o

.PHONY: all clean