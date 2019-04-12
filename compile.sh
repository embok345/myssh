#!/bin/bash

if [ "$1" == "-d" ]; then
  gcc *.c -g -o myssh -L../bignum/bin/static/ -I../bignum/src/ -lbignum -lm -lpthread -fsanitize=address
else
  gcc *.c -g -o myssh -L../bignum/bin/static/ -I../bignum/src/ -lbignum -lm -lpthread
fi
