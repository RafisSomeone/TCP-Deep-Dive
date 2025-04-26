CC = gcc
CFLAGS = -MMD -MP -Wall -Wextra -Wshadow=local -Wconversion 
EXE = tcp_server
SRCS = $(wildcard src/*.c)
OBJECTS = $(SRCS:.c=.o)
DEPENDENCIES = $(SRCS:.c=.d)

TEST_DIR = tests
TEST_SRC = $(wildcard $(TEST_DIR)/*.c)
UNITY_SRC = $(TEST_DIR)/unity/unity.c
TEST_OBJECTS = $(TEST_SRC:.c=.o) $(UNITY_SRC:.c=.o)
TEST_EXE = test_runner
TEST_CFLAGS = $(CFLAGS) -Itests/unity -Isrc

all: $(EXE)

$(EXE): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $(EXE)

$(TEST_EXE): $(TEST_OBJECTS) $(filter-out src/main.o, $(OBJECTS))
	$(CC) $(TEST_CFLAGS) $(TEST_OBJECTS) $(filter-out src/main.o, $(OBJECTS)) -o $(TEST_EXE)

tests/%.o: tests/%.c
	$(CC) $(TEST_CFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_EXE)
	./$(TEST_EXE)

format:
	find src tests \( -maxdepth 1 -name "*.c" -o -name "*.h" \) | xargs clang-format --dry-run --Werror

clean:
	rm -f $(EXE) $(OBJECTS) $(DEPENDENCIES) $(TEST_EXE) $(TEST_OBJECTS)

-include $(DEPENDENCIES)
