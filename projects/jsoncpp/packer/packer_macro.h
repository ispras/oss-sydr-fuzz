// Copyright 2024 ISP RAS.
//
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
//
////////////////////////////////////////////////////////////////////////////////

#include <stddef.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <functional>
#include <sstream>
#include <string>
#include <type_traits>

#include "libprotobuf-mutator/port/protobuf.h"

#define DEFINE_CONVERT_PROTOBUF_TO_DATA(Proto)                                         \
  int PackPb2Data(std::string data, char *fout) {                                      \
    Proto msg;                                                                         \
    msg.Clear();                                                                       \
    google::protobuf::TextFormat::Parser parser;                                       \
    parser.SetRecursionLimit(100);                                                     \
    parser.AllowPartialMessage(true);                                                  \
    parser.AllowUnknownField(true);                                                    \
    if (!parser.ParseFromString(data, &msg)) {                                         \
      msg.Clear();                                                                     \
      std::cout << "Failed to parse protobuf Message from file" << std::endl;          \
      return 0;                                                                        \
    }                                                                                  \
    std::string result = ConvertOneProtoInput(msg);                                    \
    if (result.length() > 0) {                                                         \
      FILE *f1 = fopen(fout, "w");                                                     \
      assert(f1);                                                                      \
      fwrite(result.c_str(), 1, result.size(), f1);                                    \
      fclose(f1);                                                                      \
      return 0;                                                                        \
    }                                                                                  \
    else { return 1; }                                                                 \
  }

#define DEFINE_CONVERT_DATA_TO_PROTOBUF(Proto)                                         \
  int PackData2Pb(std::string data, char *fout) {                                      \
    Proto msg;                                                                         \
    msg.Clear();                                                                       \
    /* convert string -> Proto message */                                              \
    ConvertOneDataInput(msg, data);                                                    \
    /* Message -> data bytes (string) */                                               \
    std::string result;                                                                \
    if (!google::protobuf::TextFormat::PrintToString(msg, &result)) {                  \
      std::cout << "Failed to deserialize Message to raw data string" << std::endl;    \
      return 0;                                                                        \
    }                                                                                  \
    if (result.length() == 0)                                                          \
    {                                                                                  \
      std::cout << "Failed: result string is empty for " << fout << std::endl;         \
      return 0;                                                                        \
    }                                                                                  \
    /* Write data bytes to file */                                                     \
    FILE *f1 = fopen(fout, "w");                                                       \
    assert(f1);                                                                        \
    fwrite(result.c_str(), 1, result.size(), f1);                                      \
    fclose(f1);                                                                        \
    return 0;                                                                          \
  }

// NOTE: ConvertOneInput saves result to `std::string result`
#define DEFINE_CONVERT_PB(arg)                                                         \
  static std::string ConvertOneProtoInput(arg);                                        \
  using PackerProtoType =                                                              \
      packer::PbGetFirstParam< decltype(&ConvertOneProtoInput)>::type;                 \
  DEFINE_CONVERT_PROTOBUF_TO_DATA(PackerProtoType);                                    \
  static std::string ConvertOneProtoInput(arg)


// NOTE: ConvertOneDataInput saves result to `arg1` (Message)
#define DEFINE_CONVERT_DATA(arg1, arg2)                                                \
  static void ConvertOneDataInput(arg1, arg2);                                         \
  using PackerProtoType =                                                              \
      packer::DataGetFirstParam< decltype(&ConvertOneDataInput)>::type;                \
  DEFINE_CONVERT_DATA_TO_PROTOBUF(PackerProtoType);                                    \
  static void ConvertOneDataInput(arg1, arg2)

namespace packer {

template <typename T>
struct PbGetFirstParam;

template <class Arg>
struct PbGetFirstParam<std::string (*)(Arg)> {
  using type = typename std::remove_const<
      typename std::remove_reference<Arg>::type>::type;
};

template <typename T>
struct DataGetFirstParam;

template <class Arg1, class Arg2>
struct DataGetFirstParam<void (*)(Arg1, Arg2)> {
  using type = typename std::remove_reference<Arg1>::type;
};

}  // namespace packer
