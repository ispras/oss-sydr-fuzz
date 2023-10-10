#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "libcue.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  char *fuzz_data = (char *)malloc(Size + 1);
  memcpy(fuzz_data, Data, Size);
  fuzz_data[Size] = '\0';
  Cd *cd = cue_parse_string (fuzz_data);
  cd_delete(cd);
  free(fuzz_data);
  return 0;  // Values other than 0 and -1 are reserved for future use.
}

