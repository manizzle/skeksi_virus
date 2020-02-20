all: virus
virus:
	gcc -O0 -DANTIDEBUG -DINFECT_PLTGOT  -fno-stack-protector -c virus.c -fpic -o virus.o
	#gcc -g -DDEBUG -O0 -fno-stack-protector -c virus.c -fpic -mcmodel=small -o virus.o
	gcc -N -fno-stack-protector -nostdlib virus.o -o virus
detect:
	gcc detect.c /opt/elfmaster/lib/libelfmaster.a -I/opt/elfmaster/include -o detect	
test: virus detect
	gcc test.c -o test
	./test
	./detect test
	./virus test
	./test
	./detect test

clean:
	rm -f virus
