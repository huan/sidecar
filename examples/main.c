#include <unistd.h>
#include <stdio.h>

char message[100] = {0};
int counter = 0;

char* random () {
  sprintf(message, "message#%d", ++counter);
  return message;
}

void receive (char* content) {
  printf("< %s\n", content);
}

void send (char* content) {
  printf("> %s\n", content);
}

int main() {
  printf("receive() is at %p\n", receive);
  printf("send() is at %p\n", send);

  send("Sidecar demo started.");

  while(1) {
    receive(randome());
    sleep(5);
  }

  return 0;
}
