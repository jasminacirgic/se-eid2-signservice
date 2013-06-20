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

import com.aaasec.sigserv.cscommon.marshaller.XmlBeansUtil;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Document;

/**
 * XML Utils.
 */
public class XmlUtils {

    private final static Logger LOG = Logger.getLogger(XmlUtils.class.getName());


    public static String getDocText(Document doc) {
        try {
            byte[] xmlBytes = XmlBeansUtil.getStyledBytes(XmlObject.Factory.parse(doc));
            return new String(xmlBytes, Charset.forName("UTF-8"));
        } catch (Exception ex) {
        }
        return "";
    }

    public static byte[] getCanonicalDocText(Document doc) {
        try {
            return XmlBeansUtil.getBytes(XmlObject.Factory.parse(doc));
        } catch (Exception ex) {
        }
        return null;
    }

    public static Document loadXMLConf(File xmlFile) {
        Document doc;
        try {
            InputStream is = new FileInputStream(xmlFile);

            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            doc = dBuilder.parse(is);
            doc.getDocumentElement().normalize();

        } catch (Exception ex) {
            LOG.log(Level.INFO, null, ex);
            return null;
        }

        return doc;

    }

    public static String getParsedXMLText(File xmlFile) {
        return getDocText(loadXMLConf(xmlFile));
    }
}
