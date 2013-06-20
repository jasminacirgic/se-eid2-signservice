/*
 * Copyright 2013 Swedish E-identification Board (E-legitimationsnämnden)
 *  		 
 *   Licensed under the EUPL, Version 1.1 or ñ as soon they will be approved by the 
 *   European Commission - subsequent versions of the EUPL (the "Licence");
 *   You may not use this work except in compliance with the Licence. 
 *   You may obtain a copy of the Licence at:
 * 
 *   http://joinup.ec.europa.eu/software/page/eupl 
 * 
 *   Unless required by applicable law or agreed to in writing, software distributed 
 *   under the Licence is distributed on an "AS IS" basis,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or 
 *   implied.
 *   See the Licence for the specific language governing permissions and limitations 
 *   under the Licence.
 */
package com.aaasec.sigserv.cscommon;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;

/**
 * File operations
 */
public class FileOps implements Constants {
    
    private static final Logger LOG = Logger.getLogger(FileOps.class.getName());
    
    public static String readTextFile(File textFile) {
        StringBuilder b = new StringBuilder();
        
        if (textFile.canRead()) {
            //...checks on file
            try {
                //use buffering, reading one line at a time
                //FileRe   ader always assumes default encoding is OK!
                BufferedReader input = new BufferedReader(new FileReader(textFile));
                try {
                    String line = null; //not declared within while loop
                    /*
                     * readLine is a bit quirky :
                     * it returns the content of a line MINUS the newline.
                     * it returns null only for the END of the stream.
                     * it returns an empty String if two newlines appear in a row.
                     */
                    while ((line = input.readLine()) != null) {
                        b.append(line).append(LF);
                    }
                } finally {
                    input.close();
                }
            } catch (IOException ex) {
                LOG.warning(ex.getMessage());
            }
        }
        
        return b.toString();
    }
    
    public static List<String> readTextLineFile(File textFile) {
        List<String> fileLines = new LinkedList<String>();
        
        if (textFile.canRead()) {
            try {
                BufferedReader input = new BufferedReader(new FileReader(textFile));
                try {
                    String line = null;
                    while ((line = input.readLine()) != null) {
                        fileLines.add(line);
                    }
                } finally {
                    input.close();
                }
            } catch (IOException ex) {
                LOG.warning(ex.getMessage());
            }
        }
        return fileLines;
    }
    
    public static byte[] readBinaryFile(File file) {
        List inp = new LinkedList<Byte>();
        try {
            FileInputStream fi = new FileInputStream(file);
            while (fi.available() > 0) {
                inp.add(fi.read());
            }
        } catch (IOException ex) {
            LOG.log(Level.WARNING, null, ex);
            return new byte[0];
        }
        byte[] b = new byte[inp.size()];
        int i = 0;
        for (Object o : inp) {
            int val = (Integer) o;
            b[i++] = (byte) val;
        }
        return b;
    }
    
    public static String openAndReadTextFile(File fileDir) {
        JFileChooser fc = new JFileChooser(fileDir);
        int returnVal = fc.showOpenDialog(fc);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            if (file.canRead()) {
                String result = readTextFile(file);
                return result;
            }
        }
        return null;
    }
    
    public static byte[] openAndReadBinaryFile(File fileDir) {
        JFileChooser fc = new JFileChooser(fileDir);
        int returnVal = fc.showOpenDialog(fc);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            if (file.canRead()) {
                byte[] result = readBinaryFile(file);
                return result;
            }
        }
        return null;
    }
    
    public static void saveTxtFile(File file, String data) {
        File dir = file.getParentFile();
        if (dir != null) {
            dir.mkdirs();
        }
        
        try {
            Writer output = null;
            output = new BufferedWriter(new FileWriter(file));
            output.write(data);
            output.close();
            /*
             * If the selected filenamne ends with .nroff - Save the encoded output as a .txt file with same file name.
             */
        } catch (IOException ex) {
            LOG.warning(ex.getMessage());
        }
    }
    
    static public void saveByteFile(byte[] data, File file) {
        
        try {
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(data);
            fos.close();
        } catch (IOException ex) {
            LOG.warning(ex.getMessage());
        }
    }
    
    public static String getfileNameString(String path, String fileName) {
        if (path == null || fileName == null) {
            return "";
        }
        
        String name = fileName;
        if (fileName.endsWith("/")) {
            name = fileName.substring(0, fileName.length() - 1);
        }
        
        if (path.endsWith("/")) {
            return path + name;
        }
        
        return path + "/" + name;
    }

    /**
     * creates a directory with the specified name if that directory does not
     * already exists.
     *
     * @param dirName The name of the directory
     * @return true if the directory exists or was created successfully, false
     * otherwise.
     */
    public static boolean createDir(String dirName) {
        File dir = new File(dirName);
        if (!dir.exists()) {
            return dir.mkdirs();
        }
        return true;
    }
    
    public static void copy(File original, File copy) {        
        
        InputStream inStream;
        OutputStream outStream;
        
        try {
            
            inStream = new FileInputStream(original);
            outStream = new FileOutputStream(copy);
            
            byte[] buffer = new byte[1024];
            
            int length;
            //copy the file content in bytes 
            while ((length = inStream.read(buffer)) > 0) {
                
                outStream.write(buffer, 0, length);
                
            }
            
            inStream.close();
            outStream.close();
            
        } catch (IOException e) {
            LOG.warning(e.getMessage());
        }
    }
}
