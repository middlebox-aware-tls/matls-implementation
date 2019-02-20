CERT_FILE=matls_cert.crt
CA_CERT_FILE=ca_carol.pem
KEY_FILE=matls_priv.pem

SERVER=server
GCC=gcc
CFLAGS=-DLOGGER -o 
CLIENT_SRC=client.c
SERVER_SRC=server.c
TCP_SERVER_SRC=tcp_server.c
TCP_CLIENT_SRC=tcp_client.c
FLAGS=-I../../matls-compiled/include -I../include -L../../matls-compiled/lib
LDFLAGS=-lssl -lcrypto -ldl -lpthread
GDB=gdb

HOST=www.matls.com
PORT=5017
NUM_OF_THREADS=1

default: matls

matls:
	${GCC} -DMATLS ${CFLAGS} ${SERVER} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}

split:
	${GCC} ${CFLAGS} ${SERVER} ${SERVER_SRC} ${FLAGS} ${LDFLAGS}

tcp:
	${GCC} ${CFLAGS} ${SERVER} ${TCP_SERVER_SRC} ${FLAGS} ${LDFLAGS}

sstart:
	./${SERVER} ${PORT} ${CERT_FILE} ${KEY_FILE} ${LOG_FILE}

tcp_sstart:
	./${SERVER} ${PORT}

clean:
	rm ${SERVER} ${CLIENT}
