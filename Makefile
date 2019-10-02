BN_LIBRARY=/home/poulter/Coding/C_C++/bignum/bin/shared
BN_INCLUDE=/home/poulter/Coding/C_C++/bignum/src/

CC=gcc

ROOT_PATH = $(abspath $(lastword $(MAKEFILE_LIST)))
SRC_DIR = $(dir $(ROOT_PATH))src
EX_DIR = $(dir $(ROOT_PATH))bin
EX_NAME = myssh

ifeq ($(RELEASE),1)
  COMPILE_FLAGS = -O3 -w
endif
ifeq ($(DEBUG),1)
  COMPILE_FLAGS = -Og -g -Wall
endif

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(EX_DIR)/%.o,$(SRCS))

DEPS = $(wildcard $(SRC_DIR)/*.h)

LDFLAGS=-L$(BN_LIBRARY) -lm -lreadline -lpthread -lbignum
CFLAGS=$(COMPILE_FLAGS) -I$(BN_INCLUDE) -DUSE_BIGNUM

$(EX_NAME): $(EX_DIR)/$(EX_NAME)
$(EX_DIR)/$(EX_NAME): $(OBJS) $(DEPS)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)
$(OBJS): $(EX_DIR)/%.o : $(SRC_DIR)/%.c $(DEPS)
	$(CC) -c $< -o $@ $(CFLAGS)


.PHONY: clean
clean:
	rm -f bin/*.o bin/myssh
