// Copyright 2021 Google LLC
// Modifications copyright (C) 2025 ISP RAS
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
import java.io.*;
import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

public class FuzzReader {
  public static void fuzzerTestOneInput(byte[] data) {
    String input = new String(data);
    TypeAdapter<JsonElement> adapter = new Gson().getAdapter(JsonElement.class);
    boolean lenient = false;
    JsonReader reader = new JsonReader(new StringReader(input));
    reader.setLenient(lenient);
    try {
      while (reader.peek() != JsonToken.END_DOCUMENT) {
        adapter.read(reader);
      }
    } catch (JsonParseException | IllegalStateException | NumberFormatException | IOException expected) { }
  }
}
