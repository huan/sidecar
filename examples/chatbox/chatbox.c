#include <unistd.h>
#include <stdio.h>

char buf[100] = {0};
int counter = 0;

char* randomMessage (const char* type) {
  sprintf(buf, "Messaging: %s message#%d", type, counter);
  return buf;
}

void mo (char* content) {
  printf("> %s\n", content);
}

void mt (char* content) {
  printf("<< %s\n", content);
}

int main() {
  printf("mo() is at %p\n", mo);
  printf("mt() is at %p\n", mt);

  mo("Chatbox demo started.");

  while(++counter) {

    if (counter % 3 == 0) {
      mo(randomMessage("Send"));
    } else {
      mt(randomMessage("Receive"));
    }

    sleep(3);
  }

  return 0;
}
