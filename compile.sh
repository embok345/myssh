#!/bin/bash

if [ "$1" == "-d" ]; then
  gcc *.c -g -o myssh -L../bignum/bin/static/ -I../bignum/src/ -lbignum -lm -lpthread -fsanitize=address -DUSE_BIGNUM
else
  gcc *.c -g -o myssh -L../bignum/bin/static/ -I../bignum/src/ -lbignum -lm -lpthread -lreadline -DUSE_BIGNUM
fi
