// Copyright 2021 Google LLC
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
package com.google.json;

import com.google.json.JsonSanitizer;
import com.gitlab.javafuzz.core.AbstractFuzzTarget;
import java.io.UnsupportedEncodingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import com.gitlab.javafuzz.core.AbstractFuzzTarget;
import com.google.json.JsonSanitizer;
import java.io.UnsupportedEncodingException;

import java.io.UnsupportedEncodingException;

public class IdempotenceFuzzerJF extends AbstractFuzzTarget {
  @Override
  public void fuzz(byte[] data) {
    String input;
    try {
        input = new String(data, "UTF-8");
    } catch (UnsupportedEncodingException e) {
        return;
    }
    String output;
    try {
      output = JsonSanitizer.sanitize(input, 10);
    } catch (ArrayIndexOutOfBoundsException e) {
      // ArrayIndexOutOfBoundsException is expected if nesting depth is
      // exceeded.
      return;
    }

    // Ensure that sanitizing twice does not give different output
    // (idempotence). Since failure to be idempotent is not a security issue in
    // itself, fail with a regular AssertionError.
    assert JsonSanitizer.sanitize(output).equals(output) : "Not idempotent";
  }

  public static void main(String[] args) {
    if (args.length != 1) {
        System.err.println("Usage: java -jar DenylistFuzzerJFtest.jar <input-file>");
        System.exit(1);
    }

    String filePath = args[0];
    byte[] data;
    try {
        data = Files.readAllBytes(Paths.get(filePath));
    } catch (IOException e) {
        System.err.println("Error reading file: " + e.getMessage());
        System.exit(1);
        return;
    }
    
    String input;
    try {
        input = new String(data, "UTF-8");
    } catch (UnsupportedEncodingException e) {
        System.err.println("UTF-8 encoding not supported: " + e.getMessage());
        return;
    }

    String output;
    try {
        output = JsonSanitizer.sanitize(input, 10);
    } catch (ArrayIndexOutOfBoundsException e) {
        return;
    }

    assert JsonSanitizer.sanitize(output).equals(output) : "Not idempotent";
  }
  
}
