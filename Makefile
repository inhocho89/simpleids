default:
	gcc src/simpleids.c -o simpleids -lpcap
clean:
	rm simpleids
