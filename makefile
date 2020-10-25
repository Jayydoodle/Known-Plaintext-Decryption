INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	cc -I$(INC) -L$(LIB) -o findkey lab1.c -lcrypto -ldl

clean:
	rm *findkey
