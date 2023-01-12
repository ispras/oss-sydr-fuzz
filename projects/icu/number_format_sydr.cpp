// © 2019 and later: Unicode, Inc. and others.
// License & terms of use: http://www.unicode.org/copyright.html

// Fuzzer for NumberFormat::parse.

#include <cstring>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <memory>
#include "fuzzer_utils.h"
#include "unicode/numfmt.h"

IcuEnvironment* env = new IcuEnvironment();

int main(int argc, char** argv)
{
  UErrorCode status = U_ZERO_ERROR;
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

  std::unique_ptr<icu::NumberFormat> fmt(
      icu::NumberFormat::createInstance(locales[rnd], status));
  if (U_FAILURE(status)) {
    return 0;
  }

  icu::UnicodeString fuzzstr(false, fuzzbuff.get(), unistr_size);
  icu::Formattable result;
  fmt->parse(fuzzstr, result, status);

  return 0;
}
