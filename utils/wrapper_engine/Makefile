# (aastham) Fixed circular dependency - was causing libFuzzingEngine.a to be created as directory instead of file
libFuzzingEngine.a: main.c Makefile
	gcc -g -Wall -Wextra -static -c main.c
	ar cr libFuzzingEngine.a *.o
