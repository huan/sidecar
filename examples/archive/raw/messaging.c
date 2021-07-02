#include <unistd.h>
#include <stdio.h>

char buf[100] = {0};
int counter = 0;

char* message (const char* type) {
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

  mo("Messaging demo started.");

  while(++counter) {
    mt(message("Receive"));

    if (counter % 3 == 0) {
      mo(message("Send"));
    }

    sleep(3);
  }

  return 0;
}
