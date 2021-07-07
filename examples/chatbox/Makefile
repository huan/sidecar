# Credit: https://stackoverflow.com/a/14777895/1123955
ifeq ($(OS),Windows_NT)
    detected_OS := win32
else
    detected_OS := $(shell sh -c 'uname 2>/dev/null | tr "[:upper:]" "[:lower:]"')
endif

# https://stackoverflow.com/a/10305055/1123955
all:
	-@make $(detected_OS)

linux: chatbox.c
	gcc -o chatbox-$(detected_OS) chatbox.c

mac: chatbox.c
	gcc -o chatbox-$(detected_OS) chatbox.c

win32: chatbox.c
	cl.exe /Fe:chatbox-$(detected_OS) chatbox.c

clean:
	rm -f chatbox-$(detected_OS)

chatbox:
	./chatbox-$(detected_OS)
