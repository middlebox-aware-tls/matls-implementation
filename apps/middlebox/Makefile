GCC=gcc
RM=rm
FLAGS=-I../../matls-compiled/include -I../include -L../../matls-compiled/lib
CFLAGS=-DLOGGER -o
LDFLAGS=-lssl -lcrypto -ldl -lpthread

HOST=127.0.0.1
PORT=5555
NUM_OF_THREADS=1

MB_SRC=mb.c mssl.c table.c common.c 
SMB_SRC=smb.c mssl.c table.c common.c 
CMB_SRC=cmb.c mssl.c table.c common.c
TCP_SRC=tcp_mb.c table.c common.c
SRC=mssl.c table.c common.c 
MB_OBJ=mb.o mssl.o table.o common.o

MB=mb
MB_1=mb1
MB_2=mb2
MB_3=mb3
MB_4=mb4
MB_5=mb5
MB_6=mb6
MB_7=mb7
MB_8=mb8
MB_9=mb9
MB_10=mb10
MB_11=mb11
MB_12=mb12
MB_13=mb13
MB_14=mb14
MB_15=mb15
MB_16=mb16
SMB=smb
CMB=cmb

PORT_1=5001
PORT_2=5002
PORT_3=5003
PORT_4=5004
PORT_5=5005
PORT_6=5006
PORT_7=5007
PORT_8=5008
PORT_9=5009
PORT_10=5010
PORT_11=5011
PORT_12=5012
PORT_13=5013
PORT_14=5014
PORT_15=5015
PORT_16=5016
PORT_SMB=5017
PORT_CMB=5017

KEY_1=certs/1.key
KEY_2=certs/2.key
KEY_3=certs/3.key
KEY_4=certs/4.key
KEY_5=certs/5.key
KEY_6=certs/6.key
KEY_7=certs/7.key
KEY_8=certs/8.key
KEY_9=certs/9.key
KEY_10=certs/10.key
KEY_11=certs/11.key
KEY_12=certs/12.key
KEY_13=certs/13.key
KEY_14=certs/14.key
KEY_15=certs/15.key
KEY_16=certs/16.key
KEY_CMB1=certs/cmb1.key
KEY_SMB1=certs/smb1.key
KEY_CMB2=certs/cmb2.key
KEY_SMB2=certs/smb2.key

CERT_1=certs/1.pem
CERT_2=certs/2.pem
CERT_3=certs/3.pem
CERT_4=certs/4.pem
CERT_5=certs/5.pem
CERT_6=certs/6.pem
CERT_7=certs/7.pem
CERT_8=certs/8.pem
CERT_9=certs/9.pem
CERT_10=certs/10.pem
CERT_11=certs/11.pem
CERT_12=certs/12.pem
CERT_13=certs/13.pem
CERT_14=certs/14.pem
CERT_15=certs/15.pem
CERT_16=certs/16.pem
CERT_CMB1=certs/cmb1.pem
CERT_SMB1=certs/smb1.pem
CERT_CMB2=certs/cmb2.pem
CERT_SMB2=certs/smb2.pem

FORWARD_FILE_1=forward/forward_1.txt
FORWARD_FILE_2=forward/forward_2.txt
FORWARD_FILE_3=forward/forward_3.txt
FORWARD_FILE_4=forward/forward_4.txt
FORWARD_FILE_5=forward/forward_5.txt
FORWARD_FILE_6=forward/forward_6.txt
FORWARD_FILE_7=forward/forward_7.txt
FORWARD_FILE_8=forward/forward_8.txt
FORWARD_FILE_9=forward/forward_9.txt
FORWARD_FILE_10=forward/forward_10.txt
FORWARD_FILE_11=forward/forward_11.txt
FORWARD_FILE_12=forward/forward_12.txt
FORWARD_FILE_13=forward/forward_13.txt
FORWARD_FILE_14=forward/forward_14.txt
FORWARD_FILE_15=forward/forward_15.txt
FORWARD_FILE_16=forward/forward_16.txt
FORWARD_FILE_CMB=forward/forward_cmb.txt
FORWARD_FILE_SMB=forward/forward_smb.txt
FORWARD_FILE_CMB1=forward/forward_cmb1.txt
FORWARD_FILE_SMB1=forward/forward_smb1.txt
FORWARD_FILE_CMB2=forward/forward_cmb2.txt
FORWARD_FILE_SMB2=forward/forward_smb2.txt

default: matls

matls:
	${GCC} -DMATLS ${CFLAGS} ${MB_1} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_2} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_3} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_4} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_5} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_6} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_7} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_8} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_9} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_10} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_11} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_12} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_13} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_14} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_15} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${MB_16} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${SMB}	${SMB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} -DMATLS ${CFLAGS} ${CMB} ${CMB_SRC} ${FLAGS} ${LDFLAGS}

split:
	${GCC} ${CFLAGS} ${MB_1} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_2} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_3} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_4} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_5} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_6} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_7} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_8} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_9} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_10} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_11} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_12} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_13} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_14} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_15} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_16} ${MB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SMB} ${SMB_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${CMB} ${CMB_SRC} ${FLAGS} ${LDFLAGS}

tcp:
	${GCC} ${CFLAGS} ${MB_1} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_2} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_3} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_4} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_5} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_6} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_7} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_8} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_9} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_10} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_11} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_12} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_13} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_14} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_15} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${MB_16} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${SMB} ${TCP_SRC} ${FLAGS} ${LDFLAGS}
	${GCC} ${CFLAGS} ${CMB} ${TCP_SRC} ${FLAGS} ${LDFLAGS}

read:
	./${MB_1} ${PORT_1} ${CERT_FILE} ${KEY_FILE} ${FORWARD_FILE_1} 0 0

write:
	./${MB_2} ${PORT_2} ${CERT_FILE} ${KEY_FILE} ${FORWARD_FILE_2} 0 1

mstart1:
	./${MB_1} ${PORT_1} ${CERT_1} ${KEY_1} ${FORWARD_FILE_1} 0 0

mstart2:
	./${MB_2} ${PORT_2} ${CERT_2} ${KEY_2} ${FORWARD_FILE_2} 0 0

mstart3:
	./${MB_3} ${PORT_3} ${CERT_3} ${KEY_3} ${FORWARD_FILE_3} 0 0

mstart4:
	./${MB_4} ${PORT_4} ${CERT_4} ${KEY_4} ${FORWARD_FILE_4} 0 0

mstart5:
	./${MB_5} ${PORT_5} ${CERT_5} ${KEY_5} ${FORWARD_FILE_5} 0 0

mstart6:
	./${MB_6} ${PORT_6} ${CERT_6} ${KEY_6} ${FORWARD_FILE_6} 0 0

mstart7:
	./${MB_7} ${PORT_7} ${CERT_7} ${KEY_7} ${FORWARD_FILE_7} 0 0

mstart8:
	./${MB_8} ${PORT_8} ${CERT_8} ${KEY_8} ${FORWARD_FILE_8} 0 0

mstart9:
	./${MB_9} ${PORT_9} ${CERT_9} ${KEY_9} ${FORWARD_FILE_9} 0 0

mstart10:
	./${MB_10} ${PORT_10} ${CERT_10} ${KEY_10} ${FORWARD_FILE_10} 0 0

mstart11:
	./${MB_11} ${PORT_11} ${CERT_11} ${KEY_11} ${FORWARD_FILE_11} 0 0

mstart12:
	./${MB_12} ${PORT_12} ${CERT_12} ${KEY_12} ${FORWARD_FILE_12} 0 0

mstart13:
	./${MB_13} ${PORT_13} ${CERT_13} ${KEY_13} ${FORWARD_FILE_13} 0 0

mstart14:
	./${MB_14} ${PORT_14} ${CERT_14} ${KEY_14} ${FORWARD_FILE_14} 0 0

mstart15:
	./${MB_15} ${PORT_15} ${CERT_15} ${KEY_15} ${FORWARD_FILE_15} 0 0

mstart16:
	./${MB_16} ${PORT_16} ${CERT_16} ${KEY_16} ${FORWARD_FILE_16} 0 0

cmstart1:
	./${CMB} ${PORT_CMB} ${CERT_CMB1} ${KEY_CMB1} ${FORWARD_FILE_CMB1} 0 0 ${LOG_FILE}

smstart1:
	./${SMB} ${PORT_SMB} ${CERT_SMB1} ${KEY_SMB1} ${FORWARD_FILE_SMB1} 1 0 smb1.txt ${LOG_FILE}

cmstart2:
	./${CMB} ${PORT_CMB} ${CERT_CMB2} ${KEY_CMB2} ${FORWARD_FILE_CMB2} 0 0 ${LOG_FILE}

smstart2:
	./${SMB} ${PORT_SMB} ${CERT_SMB2} ${KEY_SMB2} ${FORWARD_FILE_SMB2} 1 0 smb2.txt ${LOG_FILE}

mstart1w:
	./${MB_1} ${PORT_1} ${CERT_1} ${KEY_1} ${FORWARD_FILE_1} 0 1

mstart2w:
	./${MB_2} ${PORT_2} ${CERT_2} ${KEY_2} ${FORWARD_FILE_2} 0 2

mstart3w:
	./${MB_3} ${PORT_3} ${CERT_3} ${KEY_3} ${FORWARD_FILE_3} 0 3

mstart4w:
	./${MB_4} ${PORT_4} ${CERT_4} ${KEY_4} ${FORWARD_FILE_4} 0 4

mstart5w:
	./${MB_5} ${PORT_5} ${CERT_5} ${KEY_5} ${FORWARD_FILE_5} 0 5

mstart6w:
	./${MB_6} ${PORT_6} ${CERT_6} ${KEY_6} ${FORWARD_FILE_6} 0 6

mstart7w:
	./${MB_7} ${PORT_7} ${CERT_7} ${KEY_7} ${FORWARD_FILE_7} 0 7

mstart8w:
	./${MB_8} ${PORT_8} ${CERT_8} ${KEY_8} ${FORWARD_FILE_8} 0 8

mstart9w:
	./${MB_9} ${PORT_9} ${CERT_9} ${KEY_9} ${FORWARD_FILE_9} 0 9

mstart10w:
	./${MB_10} ${PORT_10} ${CERT_10} ${KEY_10} ${FORWARD_FILE_10} 0 10

mstart11w:
	./${MB_11} ${PORT_11} ${CERT_11} ${KEY_11} ${FORWARD_FILE_11} 0 11

mstart12w:
	./${MB_12} ${PORT_12} ${CERT_12} ${KEY_12} ${FORWARD_FILE_12} 0 12

mstart13w:
	./${MB_13} ${PORT_13} ${CERT_13} ${KEY_13} ${FORWARD_FILE_13} 0 13

mstart14w:
	./${MB_14} ${PORT_14} ${CERT_14} ${KEY_14} ${FORWARD_FILE_14} 0 14

mstart15w:
	./${MB_15} ${PORT_15} ${CERT_15} ${KEY_15} ${FORWARD_FILE_15} 0 15

mstart16w:
	./${MB_16} ${PORT_16} ${CERT_16} ${KEY_16} ${FORWARD_FILE_16} 0 16

cmstartw1:
	./${CMB} ${PORT_CMB} ${CERT_CMB1} ${KEY_CMB1} ${FORWARD_FILE_CMB1} 0 1

smstartw1:
	./${SMB} ${PORT_SMB} ${CERT_SMB1} ${KEY_SMB1} ${FORWARD_FILE_SMB1} 1 16 smb1.txt

cmstartw2:
	./${CMB} ${PORT_CMB} ${CERT_CMB2} ${KEY_CMB2} ${FORWARD_FILE_CMB2} 0 2

smstartw2:
	./${SMB} ${PORT_SMB} ${CERT_SMB2} ${KEY_SMB2} ${FORWARD_FILE_SMB2} 1 16 smb2.txt

mstart1t:
	./${MB_1} ${PORT_1} ${FORWARD_FILE_1} 0

mstart2t:
	./${MB_2} ${PORT_2} ${FORWARD_FILE_2} 0

mstart3t:
	./${MB_3} ${PORT_3} ${FORWARD_FILE_3} 0

mstart4t:
	./${MB_4} ${PORT_4} ${FORWARD_FILE_4} 0

mstart5t:
	./${MB_5} ${PORT_5} ${FORWARD_FILE_5} 0

mstart6t:
	./${MB_6} ${PORT_6} ${FORWARD_FILE_6} 0

mstart7t:
	./${MB_7} ${PORT_7} ${FORWARD_FILE_7} 0

mstart8t:
	./${MB_8} ${PORT_8} ${FORWARD_FILE_8} 0

mstart9t:
	./${MB_9} ${PORT_9} ${FORWARD_FILE_9} 0

mstart10t:
	./${MB_10} ${PORT_10} ${FORWARD_FILE_10} 0

mstart11t:
	./${MB_11} ${PORT_11} ${FORWARD_FILE_11} 0

mstart12t:
	./${MB_12} ${PORT_12} ${FORWARD_FILE_12} 0

mstart13t:
	./${MB_13} ${PORT_13} ${FORWARD_FILE_13} 0

mstart14t:
	./${MB_14} ${PORT_14} ${FORWARD_FILE_14} 0

mstart15t:
	./${MB_15} ${PORT_15} ${FORWARD_FILE_15} 0

mstart16t:
	./${MB_16} ${PORT_16} ${FORWARD_FILE_16} 0

cmstart1t:
	./${CMB} ${PORT_CMB} ${FORWARD_FILE_CMB1} 0

smstart1t:
	./${SMB} ${PORT_SMB} ${FORWARD_FILE_SMB1} 0

cmstart2t:
	./${CMB} ${PORT_CMB} ${FORWARD_FILE_CMB2} 0

smstart2t:
	./${SMB} ${PORT_SMB} ${FORWARD_FILE_SMB2} 0

clean:
	${RM} ${MB_1} ${MB_2} ${MB_3} ${MB_4} ${MB_5} ${MB_6} ${MB_7} ${MB_8} ${MB_9} ${MB_10} ${MB_11} ${MB_12} ${MB_13} ${MB_14} ${MB_15} ${MB_16} ${SMB} ${CMB}
