GCC=gcc
CFLAGS=-DLOGGER -o 

CLIENT=client
CLIENT_SRC=client.c
TCP_CLIENT_SRC=tcp_client.c

FLAGS=-I../../matls-compiled/include -I../include -L../../matls-compiled/lib
LDFLAGS=-lssl -lcrypto -ldl -lpthread

HOST=www.matls.com
PORT=5017
NUM_OF_THREADS=1

default: matls

matls:
	${GCC} -DMATLS ${CFLAGS} ${CLIENT} ${CLIENT_SRC} ${FLAGS} ${LDFLAGS}

split:
	${GCC} ${CFLAGS} ${CLIENT} ${CLIENT_SRC} ${FLAGS} ${LDFLAGS}

tcp:
	${GCC} ${CFLAGS} ${CLIENT} ${TCP_CLIENT_SRC} ${FLAGS} ${LDFLAGS}

cstart:
	./${CLIENT} ${HOST} ${PORT} 1 ${LOG_FILE}

tcp_cstart:
	./${CLIENT} ${HOST} ${PORT} 1 ${LOG_FILE}

clean:
	rm ${SERVER} ${CLIENT}
