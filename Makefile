#CC = gcc -I/home/ashish/test/kernel/linux.git/include

#	CFLAGS = -O2 -D__KERNEL__ -Wall

obj-m := simple_entry.o

all:
	make -C /lib/modules/4.13.0-21-generic/build M=$(PWD) modules

clean:
	make -C /lib/modules/4.13.0-21-generic/build M=$(PWD) clean

install:
	/sbin/insmod simple_entry

remove:
	/sbin/rmmod simple_entry
