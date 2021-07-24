#include <stdio.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>

int main (int argc, char** argv) {
  void *handle;
  uint64_t (*factorial)(int);
  char *error;

  handle = dlopen("libfactorial.dylib", RTLD_LAZY);
  if (!handle) {
      fprintf(stderr, "%s\n", dlerror());
      exit(EXIT_FAILURE);
  }

  dlerror();    /* Clear any existing error */

  factorial = (uint64_t (*)(int)) dlsym(handle, "factorial");

  error = dlerror();
  if (error != NULL) {
      fprintf(stderr, "%s\n", error);
      exit(EXIT_FAILURE);
  }

  printf("%llu\n", (*factorial)(3));
  dlclose(handle);
  exit(EXIT_SUCCESS);
}
