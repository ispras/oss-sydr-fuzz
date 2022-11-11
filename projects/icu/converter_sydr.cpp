// © 2019 and later: Unicode, Inc. and others.
// License & terms of use: http://www.unicode.org/copyright.html

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <functional>
#include <memory>
#include <vector>

#include "fuzzer_utils.h"
#include "unicode/unistr.h"
#include "unicode/ucnv.h"

IcuEnvironment* env = new IcuEnvironment();

template <typename T>
using deleted_unique_ptr = std::unique_ptr<T, std::function<void(T*)>>;

int main(int argc, char** argv)
{
  UErrorCode status = U_ZERO_ERROR;
  deleted_unique_ptr<UConverter> convs[ucnv_countAvailable()];

  for (uint16_t i = 0; i < ucnv_countAvailable(); ++i)
  {
    const char* converter_name = ucnv_getAvailableName(i);
    deleted_unique_ptr<UConverter> converter(ucnv_open(converter_name, &status),
                                           &ucnv_close);
    convs[i] = std::move(converter);
    if (U_FAILURE(status)) {
      return 0;
    }
  }

  static const size_t dest_buffer_size = 1024 * 1204;
  static const std::unique_ptr<char[]> dest_buffer(new char[dest_buffer_size]);

  FILE* fd = fopen(argv[1], "rb");
  if (!fd) return 1;
  fseek(fd, 0, SEEK_END);
  long size = ftell(fd);
  fseek(fd, 0, SEEK_SET);
  char* buffer = (char*)malloc(size);
  fread(buffer, 1, size, fd);
  fclose(fd);

  if (size < 2) {
    return 0;
  }

  uint16_t rnd = *(reinterpret_cast<const uint16_t *>(buffer));
  buffer = buffer + 2;
  size = size - 2;

  size_t unistr_size = size/2;
  std::unique_ptr<char16_t[]> fuzzbuff(new char16_t[unistr_size]);
  std::memcpy(fuzzbuff.get(), buffer, unistr_size * 2);
  icu::UnicodeString fuzzstr(false, fuzzbuff.get(), unistr_size);

  auto conv = convs[rnd % ucnv_countAvailable()].get();
  fuzzstr.extract(dest_buffer.get(), dest_buffer_size, conv, status);

  return 0;
}
