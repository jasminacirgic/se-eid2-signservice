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
package com.aaasec.sigserv.cscommon.marshaller;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlOptions;

/**
 * XML Beans utils.
 */
public class XmlBeansUtil {

    private static final Map<String, String> prefixMap = new HashMap<String, String>();
    public static final XmlOptions styled;
    public static final XmlOptions styledNoHeader;
    public static final XmlOptions noHeader;
    public static final XmlOptions stripWhiteSPcae;

    static {
        prefixMap.put("urn:se:tillvaxtverket:tsltrust:1.0:sigval:report", "tslt");
        prefixMap.put("http://www.w3.org/2000/09/xmldsig#", "ds");
        prefixMap.put("urn:oasis:names:tc:SAML:2.0:assertion", "saml");
        prefixMap.put("urn:oasis:names:tc:SAML:1.0:assertion", "saml1");
        prefixMap.put("http://www.w3.org/2001/XMLSchema", "xs");
        prefixMap.put("http://www.w3.org/2001/XMLSchema-instance", "xsi");
        prefixMap.put("http://id.elegnamnden.se/csig/1.0/dss-ext/ns", "eid2");
        prefixMap.put("urn:oasis:names:tc:dss:1.0:core:schema", "dss");
        prefixMap.put("http://id.elegnamnden.se/auth-cont/1.0/saml", "saci");

        styled = new XmlOptions().setSavePrettyPrint().setSavePrettyPrintIndent(4);
        styled.setSaveSuggestedPrefixes(prefixMap);
        styled.setSaveCDataLengthThreshold(10000);
        styled.setSaveCDataEntityCountThreshold(50);

        styledNoHeader = new XmlOptions().setSavePrettyPrint().setSavePrettyPrintIndent(4);
        styledNoHeader.setSaveSuggestedPrefixes(prefixMap);
        styledNoHeader.setSaveCDataLengthThreshold(10000);
        styledNoHeader.setSaveCDataEntityCountThreshold(50);
        styledNoHeader.setSaveNoXmlDecl();

        noHeader = new XmlOptions().setSaveNoXmlDecl();
        noHeader.setSaveSuggestedPrefixes(prefixMap);
        
        stripWhiteSPcae = new XmlOptions().setLoadStripWhitespace();
        
        
    }
    
    public static XmlObject stripWhiteSpace(XmlObject xo){
        try {
            XmlObject stripped = XmlObject.Factory.parse(xo.getDomNode(), stripWhiteSPcae);
            return stripped;
        } catch (XmlException ex) {
            return XmlObject.Factory.newInstance();
        }
    }

    public static byte[] getStyledBytes(XmlObject xo) {
        return getStyledBytes(xo, true);
    }

    public static byte[] getStyledBytes(XmlObject xo, boolean xmlHeader) {
        byte[] result = null;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            if (xmlHeader) {
                xo.save(bos, styled);
            } else {
                xo.save(bos, styledNoHeader);
            }
            result = bos.toByteArray();
            bos.close();
        } catch (IOException ex) {
            Logger.getLogger(XmlBeansUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return result;
    }

    public static byte[] getBytes(XmlObject xo) {
        return getBytes(xo, true);
    }

    public static byte[] getBytes(XmlObject xo, boolean xmlHeader) {
        byte[] result = null;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            if (xmlHeader) {
                xo.save(bos);
            } else {
                xo.save(bos, noHeader);
            }
            result = bos.toByteArray();
            bos.close();
        } catch (IOException ex) {
            Logger.getLogger(XmlBeansUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return result;
    }
}
