#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <woff2/decode.h>

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string buf;
  woff2::WOFF2StringOut out(&buf);
  out.SetMaxSize(30 * 1024 * 1024);
  woff2::ConvertWOFF2ToTTF(data, size, &out);
  return 0;
}

int main(int argc, char **argv) {
  FILE* file;
  if ((file = fopen(argv[1], "rb")) == NULL)
    return 1;

  fseek(file, 0, SEEK_END);
  size_t size = ftell(file);
  char* data = (char*)calloc(size, sizeof(char));

  fseek(file, 0, SEEK_SET);
  fread(data, 1, size, file);
  fclose(file);

  return LLVMFuzzerTestOneInput((const uint8_t*)data, size);

  free(data);
}
