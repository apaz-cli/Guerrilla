#!/bin/sh

cc guerrilla.c -o guerrilla -O3 -lcurl -fsanitize=address -ggdb3
