package io.recheck.client;
/*
Locate word that matches
five dice rolled hands.
*/

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Scanner;

public class ScanFile {

    private String needle;
    InputStream file = getClass()
            .getClassLoader().getResourceAsStream("diceware.txt");

    public ScanFile() {
        needle = null;
    }

    public String getWord(String str) {

            Scanner in = new Scanner(file);
            while (in.hasNext()) {
                String line = in.nextLine();
                if (line.contains(str)) {
                    needle = line; // match
                }
            }
        return needle;
    }
}