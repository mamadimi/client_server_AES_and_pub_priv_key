all:
	gcc client.c rsacommons.c -o client -lssl -lcrypto -O3

	gcc server.c rsacommons.c -o server -lssl -lcrypto -O3
	
clean:
	rm -f *~ *.o 

