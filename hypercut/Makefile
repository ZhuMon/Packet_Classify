BINTH=100
SPFAC=20
obj=hypercut
search=first_search
CFLAG=-DBINTH=${BINTH} -D${search} -DSPFAC=${SPFAC}

all: clean ${obj}

${obj}: ${obj}.o
	gcc -g -o ${obj} ${obj}.o -lm 

${obj}.o: ${obj}.c
	gcc -g -c ${obj}.c ${CFLAG}

clean:
	rm -f ${obj} ${obj}.o
