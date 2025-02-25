// Copyright 2023 Google LLC
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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import me.xdrop.diffutils.DiffUtils;

public class DiffUtilsFuzzer {
  public static void fuzzerTestOneInput(byte[] data) {
    String input = new String(data);
    DiffUtils.getMatchingBlocks(
      input.substring(0, input.length() / 2), input.substring(input.length() / 2));
  }
}
