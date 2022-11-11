// © 2019 and later: Unicode, Inc. and others.
// License & terms of use: http://www.unicode.org/copyright.html

// Fuzzer for ucasemap.

#include <cstring>
#include <functional>
#include <memory>
#include <stddef.h>
#include <stdint.h>
#include "fuzzer_utils.h"
#include "unicode/ucasemap.h"

IcuEnvironment* env = new IcuEnvironment();

template<typename T>
using deleted_unique_ptr = std::unique_ptr<T,std::function<void(T*)>>;

int main(int argc, char** argv) {
  UErrorCode status = U_ZERO_ERROR;
  uint8_t rnd8 = 0;
  uint16_t rnd16 = 0;
  uint32_t rnd32 = 0;

  icu::Locale *locales = new icu::Locale[65536];
  for (uint16_t i = 0; i < 0xffff; ++i)
  {
    locales[i] = GetRandomLocale(i);
  }
  locales[0xffff] = GetRandomLocale(0xffff);

  FILE* fd = fopen(argv[1], "rb");
  if (!fd) return 1;
  fseek(fd, 0, SEEK_END);
  long size = ftell(fd);
  fseek(fd, 0, SEEK_SET);
  char* data = (char*)malloc(size);
  fread(data, 1, size, fd);
  fclose(fd);

  if (size < 7) {
    return 0;
  }
  // Extract one, two, and four bytes from fuzzer data for random selection
  // purposes.
  rnd8 = *data;
  data++;
  rnd16 = *(reinterpret_cast<const uint16_t *>(data));
  data = data + 2;
  rnd32 = *(reinterpret_cast<const uint32_t *>(data));
  data = data + 4;
  size = size - 7;

  std::unique_ptr<char[]> fuzzbuff(new char[size]);
  std::memcpy(fuzzbuff.get(), data, size);

  const icu::Locale& locale = locales[rnd16];
  uint32_t open_flags = rnd32;

  deleted_unique_ptr<UCaseMap> csm(
      ucasemap_open(locale.getName(), open_flags, &status),
      [](UCaseMap* map) { ucasemap_close(map); });

  if (U_FAILURE(status)) {
    return 0;
  }

  int32_t dst_size = size * 2;
  std::unique_ptr<char[]> dst(new char[dst_size]);
  auto src = reinterpret_cast<const char*>(fuzzbuff.get());

  switch (rnd8 % 4) {
    case 0: ucasemap_utf8ToLower(csm.get(), dst.get(), dst_size, src, size,
                &status);
            break;
    case 1: ucasemap_utf8ToUpper(csm.get(), dst.get(), dst_size, src, size,
                &status);
            break;
    case 2: ucasemap_utf8ToTitle(csm.get(), dst.get(), dst_size, src, size,
                &status);
            break;
    case 3: ucasemap_utf8FoldCase(csm.get(), dst.get(), dst_size, src, size,
                &status);
            break;
  }

  return 0;
}
