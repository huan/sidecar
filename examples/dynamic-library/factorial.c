/**
 * Credit: https://github.com/node-ffi/node-ffi/tree/master/example/factorial
 *
 * To compile `libfactorial.dll` on Windows (http://stackoverflow.com/a/2220213):
 *
 * ```sh
 * cl.exe /D_USRDLL /D_WINDLL factorial.c /link /DLL /OUT:libfactorial.dll
 * ```
 *
 * To run the example:
 *
 * ```bash
 * $ node factorial.js 35
 * Your output: 6399018521010896896
 * ```
 *
 */
#include <stdint.h>

#if defined(WIN32) || defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT uint64_t factorial(int max) {
  int i = max;
  uint64_t result = 1;

  while (i >= 2) {
    result *= i--;
  }

  return result;
}
