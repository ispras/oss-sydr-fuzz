#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);

int main(int argc, char *argv[]) {
  LLVMFuzzerInitialize(&argc, &argv);

  FILE *fd = fopen(argv[1], "rb");

  if (fd == NULL)
    return 1;
  fseek(fd, 0, SEEK_END);
  int fsize = ftell(fd);
  fseek(fd, 0, SEEK_SET);

  char *buffer = (char *)malloc(sizeof(char) * fsize);
  fread(buffer, 1, fsize, fd);
  fclose(fd);

  return LLVMFuzzerTestOneInput((const uint8_t *)buffer, fsize);
}
