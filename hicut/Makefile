BINTH=100
SPFAC=8
obj=hicut_v5
CFLAG=-DBINTH=${BINTH} -DSPFAC=${SPFAC}

all: clean ${obj}

${obj}: ${obj}.o
	gcc -g -o ${obj} ${obj}.o -lm 

${obj}.o: ${obj}.c
	gcc -g -c ${obj}.c ${CFLAG} -lm

clean:
	rm -f ${obj}
	rm -f *.o
