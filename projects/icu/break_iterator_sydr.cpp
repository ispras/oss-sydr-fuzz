// © 2019 and later: Unicode, Inc. and others.
// License & terms of use: http://www.unicode.org/copyright.html

#include <cstring>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <memory>
#include <utility>
#include "fuzzer_utils.h"
#include "unicode/brkiter.h"
#include "unicode/utext.h"

IcuEnvironment* env = new IcuEnvironment();

int main(int argc, char** argv)
{
  UErrorCode status = U_ZERO_ERROR;
  icu::Locale *locales = new icu::Locale[65536];
  for (uint16_t i = 0x0; i < 0xffff; ++i)
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

  uint8_t rnd8 = 0;
  uint16_t rnd16 = 0;

  if (size < 3) {
    return 0;
  }

  // Extract one and two bytes from fuzzer data for random selection purpose.
  rnd8 = *data;
  data++;
  rnd16 = *(reinterpret_cast<const uint16_t *>(data));
  data = data + 2;
  size = size - 3;

  const icu::Locale& locale = locales[rnd16];
  std::unique_ptr<icu::BreakIterator> bi;
  switch (rnd8 % 5) {
    case 0:
      bi.reset(icu::BreakIterator::createWordInstance(locale, status));
      break;
    case 1:
      bi.reset(icu::BreakIterator::createLineInstance(locale, status));
      break;
    case 2:
      bi.reset(icu::BreakIterator::createCharacterInstance(locale, status));
      break;
    case 3:
      bi.reset(icu::BreakIterator::createSentenceInstance(locale, status));
      break;
    case 4:
      bi.reset(icu::BreakIterator::createTitleInstance(locale, status));
      break;
  }


  size_t unistr_size = size/2;
  std::unique_ptr<char16_t[]> fuzzbuff(new char16_t[unistr_size]);
  std::memcpy(fuzzbuff.get(), data, unistr_size * 2);
  UText* fuzzstr = utext_openUChars(nullptr, fuzzbuff.get(), unistr_size, &status);
  bi->setText(fuzzstr, status);
  if (U_FAILURE(status)) {
    utext_close(fuzzstr);
    return 0;
  }

  for (int32_t p = bi->first(); p != icu::BreakIterator::DONE; p = bi->next()) {}

  utext_close(fuzzstr);
  return 0;
}

