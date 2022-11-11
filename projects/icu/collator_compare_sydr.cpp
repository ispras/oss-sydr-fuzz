// © 2019 and later: Unicode, Inc. and others.
// License & terms of use: http://www.unicode.org/copyright.html

#include <cstring>

#include "fuzzer_utils.h"
#include "unicode/coll.h"
#include "unicode/localpointer.h"
#include "unicode/locid.h"

IcuEnvironment* env = new IcuEnvironment();

int main(int argc, char** argv)
{
  UErrorCode status = U_ZERO_ERROR;
  icu::LocalPointer<icu::Collator> fuzzCollator(
      icu::Collator::createInstance(icu::Locale::getUS(), status), status);
  if (U_FAILURE(status))
    return 0;
  fuzzCollator->setStrength(icu::Collator::TERTIARY);

  // Read symbolic data.
  FILE* fd = fopen(argv[1], "rb");
  if (!fd) return 1;
  fseek(fd, 0, SEEK_END);
  long size = ftell(fd);
  fseek(fd, 0, SEEK_SET);
  char* buffer = (char*)malloc(size);
  fread(buffer, 1, size, fd);
  fclose(fd);

  if (size < 2)
    return 0;
  std::unique_ptr<char16_t[]> compbuff1(new char16_t[size/4]);
  std::memcpy(compbuff1.get(), buffer, (size/4)*2);
  buffer = buffer + size/2;
  std::unique_ptr<char16_t[]> compbuff2(new char16_t[size/4]);
  std::memcpy(compbuff2.get(), buffer, (size/4)*2);

  fuzzCollator->compare(compbuff1.get(), size/4,
                        compbuff2.get(), size/4);

  return 0;

}
