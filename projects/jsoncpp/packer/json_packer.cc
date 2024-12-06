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

/* NOTE: packer is used for json-to-protobuf conversion during hybrid fuzzing
         and may contain mistakes and produce wrong parsing results (at least 
         crop spaces in strings)
*/

#include "json.pb.h"
#include "json_proto_converter.h"
#include "packer_macro.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <stdint.h>

static const char *jstr_;
static size_t size_;

json_proto::JsonObject *ParseJsonObject(size_t start, size_t end, google::protobuf::Arena &arena);
json_proto::JsonObjectList *ParseJsonObjectList(size_t start, size_t end, google::protobuf::Arena &arena);
json_proto::JsonValue *ParseJsonValue(size_t start, size_t end, google::protobuf::Arena &arena);
json_proto::NumberValue *ParseNumberValue(size_t start, size_t end, google::protobuf::Arena &arena);
json_proto::ArrayValue ParseArrayValue(size_t start, size_t end, google::protobuf::Arena &arena);
bool check_paired_braces(size_t start, size_t end);

// embodies std::string ConvertOneProtoInput(arg)
// here arg = 'const json_proto::JsonParseAPI &msg'
DEFINE_CONVERT_PB(const json_proto::JsonParseAPI &msg) {
  // Convert Message -> string
  json_proto::JsonProtoConverter converter;
  auto starter = msg.starter();
  std::string data_str = converter.Convert(starter);
  int32_t hash_settings = msg.settings();

  // Pack the data extracted from the message.
  char res[4];
  res[0] = static_cast<char>(hash_settings & 0xff);
  hash_settings = hash_settings >> 8;
  res[1] = static_cast<char>(hash_settings & 0xff);
  hash_settings = hash_settings >> 8;
  res[2] = static_cast<char>(hash_settings & 0xff);
  hash_settings = hash_settings >> 8;
  res[3] = static_cast<char>(hash_settings & 0xff);

  std::string res_str = {reinterpret_cast<const char*>(res), 4};
  res_str += data_str;

  return res_str;
}

// embodies void ConvertOneDataInput(PackerProtoType &msg, std::string data)
// here PackerProtoType = 'json_proto::JsonParseAPI'
DEFINE_CONVERT_DATA(json_proto::JsonParseAPI &msg, std::string data) {
  // Strip space symbols in given json data string.
  data.erase(std::remove(data.begin(), data.end(), '\b'), data.end());
  data.erase(std::remove(data.begin(), data.end(), '\n'), data.end());
  data.erase(std::remove(data.begin(), data.end(), '\r'), data.end());
  data.erase(std::remove(data.begin(), data.end(), '\t'), data.end());
  data.erase(std::remove(data.begin(), data.end(), '\f'), data.end());
  data.erase(std::remove(data.begin(), data.end(), ' '), data.end());
  size_ = data.size();
  jstr_ = data.c_str();
  // Skip settings bytes if this doesn't look like valid json start.
  if (size_ > 4 && jstr_[0] != '{' && jstr_[0] != '[') {
    size_ -= sizeof(uint32_t);
    jstr_ += sizeof(uint32_t);
  }

  // Parse Json
  std::string n(jstr_, size_);
  google::protobuf::Arena arena;
  json_proto::JsonStarter *st = new json_proto::JsonStarter();
  auto sym = jstr_[0];
  if ((sym == '{' || sym == '[') && check_paired_braces(0, size_)) {
    auto endpos = size_ - 1;
    // Parse JsonObjectList.
    if (sym == '{') {
      json_proto::JsonObjectList *ol = new json_proto::JsonObjectList();
      ol = ParseJsonObjectList(0, endpos, arena);
      st->set_allocated_object_list_value(ol);
    } else {
      // Parse array.
      json_proto::ArrayValue *av = new json_proto::ArrayValue();
      *av = ParseArrayValue(0, endpos, arena);
      st->set_allocated_array_value(av);
    }
    msg.set_settings(1);
    msg.set_allocated_starter(st);
  }
  else {
    std::cout << "ERROR: Json Object parsing failed - not matching braces";
  }
  return;
}

////////////////////////////////
// data2pb conversion functions:
bool validate_symbol(size_t start, size_t pos) {
  size_t cnt = 0;
  while (pos-- >= start && jstr_[pos] == '\\') {
    cnt++;
  }
  if ((cnt % 2) == 0) { return true; }
  return false;
}

// NOTE: doesn't check the order
bool check_paired_braces(size_t start, size_t end) {
  size_t cnt1 = 0;
  size_t cnt2 = 0;
  size_t p = start;
  while (p <= end) {
    char x = jstr_[p];
    if (x == '{' && validate_symbol(1, p)) cnt1++;
    if (x == '}' && validate_symbol(1, p)) cnt1--;
    if (x == '[' && validate_symbol(1, p)) cnt2++;
    if (x == ']' && validate_symbol(1, p)) cnt2--;
    p++;
  }
  if (cnt1 == 0 && cnt2 == 0) {
    return true;
  }
  return false;
}

size_t get_closing_brace(char *sym, size_t start, size_t end) {
  auto s = *sym;
  if (s != '}' && s != ']') {
    return 0;
  }
  size_t cnt = 1;
  size_t p = start + 1;
  bool is_string = false; // assume that start symbol is not inside any string value
  while (p <= end) {
    if (jstr_[p] == '"' && validate_symbol(start, p)) {
      is_string = !is_string;
      p++;
      continue;
    }
    if (is_string) {
      p++;
      continue;
    }
    char x = jstr_[p];
    if (s == '}') {
      if (x == '{' && validate_symbol(1, p)) cnt++;
      if (x == '}' && validate_symbol(1, p)) cnt--;
    } else {
      if (x == '[' && validate_symbol(1, p)) cnt++;
      if (x == ']' && validate_symbol(1, p)) cnt--;
    }
    if (cnt == 0) {
      return p;
    }
    p++;
  }
  return 0;
}

size_t get_next_symbol(const char* sym, size_t start, size_t end) {
  size_t cnt = 1;
  size_t p = start + 1;
  char s = *sym;
  if (s == '"') {
    while (p <= end) {
      if (jstr_[p] == s && validate_symbol(start, p)) {
        return p;
      }
      p++;
    }
  }
  // Assume that jstr_[start] symbol is not inside a string value.
  bool is_string = false;
  while (p <= end) {
    if (jstr_[p] == '"' && validate_symbol(start, p)) {
      is_string = !is_string;
      p++;
      continue;
    }
    if (is_string) {
      p++;
      continue;
    }
    if (jstr_[p] == s && validate_symbol(start, p)) {
      return p;
    }
    p++;
  }
  return 0;
}

size_t get_next_comma(size_t start, size_t end) {
  if (jstr_[start] == ',') { return start; }
  size_t comma = get_next_symbol(",", jstr_[start] == '"' ? start - 1 : start, end);
  while (comma) {
    if (check_paired_braces(start, comma)) return comma;
    comma = get_next_symbol(",", comma, end);
  }
  return 0;
}

json_proto::NumberValue *ParseNumberValue(size_t start, size_t end, google::protobuf::Arena &arena) {
  std::string n(jstr_ + start, end - start + 1);
  json_proto::NumberValue *nv = new json_proto::NumberValue();
  // 1. Check whether it is NumberFloat
  bool has_point = n.find(".") != std::string::npos;
  if (has_point) {
    // Parse and create NumberFloat
    json_proto::NumberFloat *nf = new json_proto::NumberFloat();
    nf->set_value(stof(n));
    nv->set_allocated_float_value(nf);
    return nv;
  }
  // 2. Check whether it is exponent
  bool has_e = n.find("e") != std::string::npos;
  bool has_E = n.find("E") != std::string::npos;
  if (has_e || has_E) {
    // Parse and create Exponent or FracExponent
    json_proto::NumberExponent *ne = new json_proto::NumberExponent();
    ne->set_use_uppercase(has_E ? true : false);
    auto e_pos = has_E ? n.find("E") : n.find("e");
    // TODO: FracExponent
    int32_t base = stoi(n.substr(0, e_pos));
    int32_t exp = stoi(n.substr(e_pos + 1, n.size() - e_pos - 1));
    ne->set_base(base);
    ne->set_exponent(exp);
    nv->set_allocated_exponent_value(ne);
    return nv;
  }
  // 3. Create NumberInteger
  json_proto::NumberInteger *ni = new json_proto::NumberInteger();
  ni->set_value(stoll(n));
  nv->set_allocated_integer_value(ni);
  return nv;
}

json_proto::ArrayValue ParseArrayValue(size_t start, size_t end, google::protobuf::Arena &arena) {
  std::string n(jstr_ + start, end - start + 1);
  json_proto::ArrayValue *av = google::protobuf::Arena::Create<json_proto::ArrayValue>(&arena);

  size_t pos = jstr_[start] == '[' ? start : get_next_symbol("[", start, end);
  size_t close_brace = get_closing_brace("]", pos, end);
  if (close_brace == 0 || (close_brace - 1) == pos) return *av;

  // Find comma within current braces level
  size_t comma = get_next_comma(pos + 1, close_brace - 1);
  // Parse first JsonValue in array.
  json_proto::JsonValue *v0 = new json_proto::JsonValue();
  v0 = ParseJsonValue(pos + 1, comma ? comma - 1 : close_brace - 1, arena);
  av->mutable_value()->AddAllocated(v0);
  while (comma) {
    pos = comma + 1;
    comma = get_next_comma(pos, close_brace - 1);
    if (comma == 0) {
      json_proto::JsonValue *v = new json_proto::JsonValue();
      v = ParseJsonValue(pos, close_brace - 1, arena);
      av->mutable_value()->AddAllocated(v);
      break;
    }
    json_proto::JsonValue *v = new json_proto::JsonValue();
    v = ParseJsonValue(pos, comma - 1, arena);
    av->mutable_value()->AddAllocated(v); 
  }
  return *av;
}


json_proto::JsonValue *ParseJsonValue(size_t start, size_t end, google::protobuf::Arena &arena) {
  std::string n(jstr_ + start, end - start + 1);
  json_proto::JsonValue *v = new json_proto::JsonValue();

  char symbol = jstr_[start];
  if (symbol == '{') {
    // Value is JsonObjectList
    json_proto::JsonObjectList *obj_list = new json_proto::JsonObjectList();
    obj_list = ParseJsonObjectList(start, end, arena);
    v->set_allocated_object_list_value(obj_list);
    return v;
  } else if (symbol == '[') {
    // Value is ArrayValue
    json_proto::ArrayValue *av = new json_proto::ArrayValue();
    *av = ParseArrayValue(start, end, arena);
    v->set_allocated_array_value(av);
    return v;
  } else if (symbol == '"') {
    // Value is StringValue
    if (jstr_[end] != '"') {
      std::cout << "ERROR: ParseJsonValue, incorrect StringValue: no matching \" at end" << std::endl;
      return v;
    }
    json_proto::StringValue *sv = new json_proto::StringValue();
    std::string st(jstr_ + start + 1, end - start - 1);
    sv->set_value(st);
    v->set_allocated_string_value(sv);
    return v;
  } else if (symbol == 't' || symbol == 'f') {
    // Value is BooleanValue
    size_t len = end - start + 1;
    if (len != 4 && len != 5) {
      std::cout << "ERROR: ParseJsonValue, incorrect Boolean, wrong len" << std::endl;
      return v;
    }
    std::string flag(jstr_ + start, len);
    if (flag != "true" && flag != "false") {
      std::cout << "ERROR: ParseJsonValue, incorrect Boolean, expect true or false" << std::endl;
      return v;
    }
    json_proto::BooleanValue *bv = new json_proto::BooleanValue();
    if (flag == "true") bv->set_value(true); else bv->set_value(false);
    v->set_allocated_boolean_value(bv);
  } else if (symbol >= '0' && symbol <= '9') {
    // Value is NumberValue
    json_proto::NumberValue *nv = new json_proto::NumberValue();
    nv = ParseNumberValue(start, end, arena);
    v->set_allocated_number_value(nv);
    return v;
  } else {
    std::cout << "ERROR: ParseJsonValue: value not any known type" << std::endl;
    return v;
  }
}


json_proto::JsonObjectList *ParseJsonObjectList(size_t start, size_t end, google::protobuf::Arena &arena) {
  std::string n(jstr_ + start, end - start + 1);
  json_proto::JsonObjectList *l =
    google::protobuf::Arena::Create<json_proto::JsonObjectList>(&arena);

  // Find next JsonObjectList start symbol.
  size_t pos = jstr_[start] == '{' ? start : get_next_symbol("{", start, end);
  size_t close_brace = get_closing_brace("}", pos, end);
  if (close_brace == 0 || (close_brace - 1) == pos) return l;
  // Find comma within current braces level
  size_t comma = get_next_comma(pos + 1, close_brace - 1);

  // Parse first JsonObject.
  json_proto::JsonObject *o = new json_proto::JsonObject();
  o = ParseJsonObject(pos + 1, comma ? comma - 1 : close_brace - 1, arena);
  l->mutable_object_value()->AddAllocated(o);
  // Cycle to parse next object after comma.
  while (comma) {
    pos = comma + 1;
    comma = get_next_comma(pos, close_brace - 1);
    if (comma == 0) {
      json_proto::JsonObject *o = new json_proto::JsonObject();
      o = ParseJsonObject(pos, close_brace - 1, arena);
      l->mutable_object_value()->AddAllocated(o);
      break;
    }
    json_proto::JsonObject *o = new json_proto::JsonObject();
    o = ParseJsonObject(pos, comma - 1, arena);
    l->mutable_object_value()->AddAllocated(o);
  }
  return l;
}

json_proto::JsonObject *ParseJsonObject(size_t start, size_t end, google::protobuf::Arena &arena) {
  std::string n(jstr_ + start, end - start + 1);
  json_proto::JsonObject *o = new json_proto::JsonObject;
  if (start + 1 >= end) { return o; }

  // Get object name.
  char sym = '"';
  size_t q = jstr_[start] == sym ? start : get_next_symbol(&sym, start, end);
  if (q == 0) {
    std::cout << "ERROR: Parse JsonObject, not found symbol \" for name string" << std::endl; return o;
  }
  auto qq = get_next_symbol(&sym, q, end);
  if (qq == 0) {
    std::cout << "ERROR: Parse JsonObject, not found second \" for name string" << std::endl; return o;
  }
  std::string o_name(jstr_ + q + 1, qq - q - 1);
  o->set_name(o_name);

  // Get object value.
  auto delim = get_next_symbol(":", qq, end);
  if (delim == 0) {
    std::cout << "ERROR: Parse JsonObject, not found symbol : after name string" << std::endl; return o;
  }
  size_t value_len = end - delim;
  std::string obj_value(jstr_ + delim + 1, value_len);
  json_proto::JsonValue *v = new json_proto::JsonValue();
  v = ParseJsonValue(delim + 1, end, arena);
  o->set_allocated_value(v);
  return o;
}
