package cz.muni.fi.keycheck.transformations;

import cz.muni.fi.keycheck.base.Params;
import cz.muni.fi.keycheck.base.Stats;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Random;
import java.util.TreeSet;

/**
 * @author Peter Sekan, peter.sekan@mail.muni.cz
 * @version 07.11.2016
 */
public class ExportToNeuralNetwork implements Stats {
    private BufferedWriter writer = null;

    public void changeCard(String icsn) {
        print();

        String fileName = icsn + ".neural.csv";
        try {
            writer = new BufferedWriter(new FileWriter(fileName));
            writer.write("nmsb;nlsb;nblen;nmod3");
            writer.newLine();
        } catch (IOException ex) {
            System.err.println("Cannot open file '" + fileName + "' for transform output.");
            writer = null;
        }
    }

    public void changeCard(String icsn, long numOfKeys) {
        changeCard(icsn);
    }

    public void process(Params params) {
        if (writer != null) {
            try {
                String line = "";
                String modulusBinary = params.getModulus().toString(2);
                line += modulusBinary.substring(0, 24) + ";";
                line += modulusBinary.substring(modulusBinary.length()-16) + ";";
                line += modulusBinary.length() + ";";
                line += params.getModulus().mod(BigInteger.valueOf(3));
                writer.write(line);
                writer.newLine();
            } catch (IOException ex) {
                System.err.println("Error on export. Cannot write to file.");
            }
        }
    }

    public void print() {
        if (writer != null) {
            try {
                writer.flush();
                writer.close();
            } catch (IOException ex) {
                System.err.println("Cannot close file for export.");
            }
        }
    }
}
