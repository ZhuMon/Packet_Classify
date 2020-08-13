BINTH=10
SPFAC=8
CFLAG=-DBINTH=${BINTH} -DSPFAC=${SPFAC}

all: clean hicut

hicut: hicut.o
	gcc -g -o hicut hicut.o -lm 

hicut.o: hicut.c
	gcc -g -c hicut.c ${CFLAG}

clean:
	rm -f hicut hicut.o
