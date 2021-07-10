/**
 *   Sidecar - https://github.com/huan/sidecar
 *
 *   @copyright 2021 Huan LI (李卓桓) <https://github.com/huan>
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>

char buf[100] = {0};
int counter = 0;

char* randomMessage (const char* type) {
  sprintf(buf, "Messaging: %s message#%d", type, counter);
  return buf;
}

int mo (char* content) {
  printf("> %s\n", content);
  return strlen(content);
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

#ifdef _WIN32
    Sleep(3000);
#else
    sleep(3);
#endif
  }

  return 0;
}
