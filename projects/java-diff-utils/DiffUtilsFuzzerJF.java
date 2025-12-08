package com.github.difflib;

import com.gitlab.javafuzz.core.AbstractFuzzTarget;

import com.github.difflib.DiffUtils;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.UnsupportedEncodingException;

public class DiffUtilsFuzzerJF extends AbstractFuzzTarget {
    @Override
    public void fuzz(byte[] data) {
        try {
            String input;
            try {
                input = new String(data, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                return;
            }
            int splitIndex = input.length() / 2;
            String first = input.substring(0, splitIndex);
            String second = input.substring(splitIndex);
            
            DiffUtils.diffInline(first, second);
        } catch (IllegalStateException e) {
            // Known exception
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
        
        try {
            String input;
            try {
                input = new String(data, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                return;
            }
            int splitIndex = input.length() / 2;
            String first = input.substring(0, splitIndex);
            String second = input.substring(splitIndex);
            
            DiffUtils.diffInline(first, second);
        } catch (IllegalStateException e) {
            // Known exception
        }
    }
}