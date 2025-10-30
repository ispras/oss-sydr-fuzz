package com.github.difflib;

import dev.fuzzit.javafuzz.core.AbstractFuzzTarget;
import com.github.difflib.DiffUtils;

public class DiffUtilsFuzzerJF extends AbstractFuzzTarget {
    @Override
    public void fuzz(byte[] data) {
        try {
            String input = new String(data, "UTF-8");
            int splitIndex = input.length() / 2;
            String first = input.substring(0, splitIndex);
            String second = input.substring(splitIndex);
            
            DiffUtils.diffInline(first, second);
        } catch (IllegalStateException e) {
            // Known exception
        } catch (Exception e) {
            // Ignore other expected exceptions
        }
    }
}