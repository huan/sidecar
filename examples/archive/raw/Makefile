all: messaging.c
	gcc -o messaging messaging.c

clean:
	rm -f messaging

.PHONY: messaging
messaging:
	./messaging

sidecar:
	ts-node sidecar.ts
