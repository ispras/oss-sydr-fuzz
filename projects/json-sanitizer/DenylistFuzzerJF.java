package com.google.json;

import com.gitlab.javafuzz.core.AbstractFuzzTarget;
import com.google.json.JsonSanitizer;
import java.io.UnsupportedEncodingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import com.gitlab.javafuzz.core.AbstractFuzzTarget;
import com.google.json.JsonSanitizer;
import java.io.UnsupportedEncodingException;

public class DenylistFuzzerJF extends AbstractFuzzTarget {
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

    // Check for forbidden substrings. As these would enable Cross-Site
    // Scripting, treat every finding as a high severity vulnerability.
   if (output.contains("</script")) {
    throw new RuntimeException("Output contains </script");
   }
   if (output.contains("]]>")) {
    throw new RuntimeException("Output contains ]]>");
   }
   if (output.contains("<script")) {
    throw new RuntimeException("Output contains <script");
   }
   if (output.contains("<!--")) {
    throw new RuntimeException("Output contains <!--");
   }
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
  }
}
