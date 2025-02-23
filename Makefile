CC = gcc
CFLAGS = -MMD -MP -Wall -Wextra -Wshadow=local -Wconversion 
EXE = tcp_server
SRCS = $(wildcard src/*.c)
OBJECTS = $(SRCS:.c=.o)
DEPENDENCIES = $(SRCS:.c=.d)

all: $(EXE)

$(EXE): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $(EXE)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXE) $(OBJECTS) $(DEPENDENCIES)

-include $(DEPENDENCIES)
