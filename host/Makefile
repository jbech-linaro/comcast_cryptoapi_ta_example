
CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

OBJS = comcast_crypto_gp_client.o \
       sec_security_openssl.o \
       sec_security_common.o

CFLAGS += -Wall -I../ta/include -I$(TEEC_EXPORT)/include -I./include -DOPTEE_DEMO
LDADD += -lteec -L$(TEEC_EXPORT)/lib

.PHONY: all
all: comcast_crypto_demo

comcast_crypto_demo: $(OBJS)
	$(CC) $(LDADD) -o $@ $^

.PHONY: clean
clean:
	rm -f $(OBJS) comcast_crypto_demo
