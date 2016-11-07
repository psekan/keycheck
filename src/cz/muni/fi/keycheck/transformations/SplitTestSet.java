package cz.muni.fi.keycheck.transformations;

import cz.muni.fi.keycheck.base.Params;
import cz.muni.fi.keycheck.base.Stats;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Random;
import java.util.TreeSet;

/**
 * @author Peter Sekan, peter.sekan@mail.muni.cz
 * @version 07.11.2016
 */
public class SplitTestSet implements Stats {
    TreeSet<Long> idOfKeys = new TreeSet<>();
    private long testSetSize = 10000;
    private Random generator = null;
    private BufferedWriter writerTestSet = null;
    private BufferedWriter writerOtherSet = null;
    long idOfKey = 0, testKeys = 0, otherKeys = 0;

    public SplitTestSet(long testSetSize) {
        this.testSetSize = testSetSize;
        try {
            generator = SecureRandom.getInstance("SHA1PRNG");
        }
        catch (NoSuchAlgorithmException ex) {
            System.err.println("NoSuchAlgorithmException SHA1PRNG: " + ex);
        }
    }

    public void changeCard(String icsn) {
        throw new RuntimeException("SplitTestSet need numOfKeys");
    }

    public void changeCard(String icsn, long numOfKeys) {
        print();
        if (testSetSize > numOfKeys) {
            System.err.println("There is not enough keys for tests in card '" + icsn + "'");
            return;
        }

        idOfKeys.clear();
        while (idOfKeys.size() < testSetSize) {
            long keyPos = generator.nextInt((int)numOfKeys);
            if (idOfKeys.contains(keyPos)) continue;
            idOfKeys.add(keyPos);
        }

        String folderPath = "test-set";
        File folder = new File(folderPath);
        if (!folder.exists() && !folder.mkdir()) {
            System.err.println("Some error occurs by creating folder '" + folderPath + "'");
            print();
            return;
        }

        try {
            writerTestSet = new BufferedWriter(new FileWriter(folderPath + "/" + icsn + ".testset.csv"));
            writerOtherSet = new BufferedWriter(new FileWriter(folderPath + "/" + icsn + ".otherset.csv"));
            writerTestSet.write("id;n;e;p;q;d;t\n");
            writerOtherSet.write("id;n;e;p;q;d;t\n");
        }
        catch (Exception ex) {
            System.err.println("Some error occurs by opening new sets: " + ex);
            print();
        }
    }

    public void process(Params params) {
        if (writerOtherSet != null && writerTestSet != null) {
            try {
                if (idOfKeys.contains(idOfKey)) {
                    params.writeToFile(writerTestSet, ++testKeys);
                } else {
                    params.writeToFile(writerOtherSet, ++otherKeys);
                }
                idOfKey++;
            } catch (Exception ex) {
                System.err.println("Some error occurs by opening new sets: " + ex);
            }
        }
    }

    public void print() {
        idOfKey = 0;
        testKeys = 0;
        otherKeys = 0;
        idOfKeys.clear();

        if (writerTestSet != null) {
            try {
                writerTestSet.flush();
                writerTestSet.close();
            } catch (IOException ex) {
                System.err.println("Cannot close file for export.");
            }
        }
        if (writerOtherSet != null) {
            try {
                writerOtherSet.flush();
                writerOtherSet.close();
            } catch (IOException ex) {
                System.err.println("Cannot close file for export.");
            }
        }
    }
}
