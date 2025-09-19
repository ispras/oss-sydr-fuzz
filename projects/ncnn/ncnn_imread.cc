#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <unistd.h>

#ifndef USE_NCNN_SIMPLEOCV
#define USE_NCNN_SIMPLEOCV
#endif

#include "ncnn/simpleocv.h"
#include "quantize/imreadwrite.h"
#include "fuzzer_temp_file.h"

#ifdef USE_NCNN_SIMPLEOCV
using namespace cv;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const FuzzerTemporaryFile file(data, size);
  const char* fname = file.filename();
  const std::string fdata(fname, 35);

  Mat matrix = cv::imread(fdata, cv::IMREAD_COLOR);

  return 0;
}

#endif
