// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
 * This fuzzer is generated by UTopia project based on TEST(Test_Tensorflow, read_inception).
 * (UTopia Project: https://github.com/Samsung/UTopia)
 */
#include <opencv2/dnn/dnn.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/imgproc.hpp>
#include <fuzzer/FuzzedDataProvider.h>
#include <fstream>

using namespace cv;
using namespace dnn;

bool saveFile(std::string Path, std::string Content) {
  std::ofstream OFS(Path);
  if (!OFS.is_open())
    return false;

  OFS << Content;
  return true;
}

static inline void fuzz(FuzzedDataProvider &Provider) {
  auto Input1 = Provider.ConsumeRandomLengthString();
  std::string Input1Path = "input1";
  if (!saveFile(Input1Path, Input1)) return;
  int Input2 = Provider.ConsumeIntegral<int>();
  auto Input3 = Provider.ConsumeRandomLengthString();
  std::string Input3Path = "input3";
  if (!saveFile(Input3Path, Input3)) return;
  int Input4 = Provider.ConsumeIntegralInRange<int>(0, 256);
  int Input5 = Provider.ConsumeIntegralInRange<int>(0, 256);
  int Input6 = Provider.ConsumeIntegralInRange<int>(0, 256);
  auto Input7 = Provider.ConsumeRandomLengthString();
  auto Input8 = Provider.ConsumeRandomLengthString();

  Net net;
  net = readNetFromTensorflow(Input1Path);
  if (net.empty())
    return;
  net.setPreferableBackend(Input2);

  Mat sample = imread(Input3Path);
  if (sample.empty())
    return;

  Mat input;
  resize(sample, input, Size(Input4, Input5));
  input -= Scalar::all(Input6);

  Mat inputBlob = blobFromImage(input);

  net.setInput(inputBlob, Input7);
  Mat out = net.forward(Input8);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider Provider(data, size);
  try {
    fuzz(Provider);
  } catch (std::exception &E) {}
  return 0;
}