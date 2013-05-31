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

import java.text.SimpleDateFormat;

/**
 * Constants
 */
public interface Constants {

    public static final String LF = System.getProperty("line.separator");
    public static final String MAC_PATH = "/Library/Application Support/EidSigServer/";
    public static final String WIN_PATH = "C:/EidSigServer/";
    public static final String PROTOCOL_BINDING = "http://id.elegnamnden.se/csig/1.0/eid2-dss/profile";
    public static final String EID2_PROTOCOL_VERSION = "1.0";
    public static final String SP_FOLDER_NAME = "SpServer";
    public static final String CS_FOLDER_NAME = "SigServer";
    public static final String SUPPORT_FOLDER_NAME = "SpSupport";
    /**
     * The maximum +- tolerance in milliseconds between claimed signing time and the current time of the signature server
     */
    public static final long MAX_SIG_TIME_TOLERANCE = 1000*60*5;  // +- 5 minutes tolerance
    /**
     * Privately defined Mime type for CMS Signed attributes 
     */
    public static final String CMS_SIGNED_ATTRIBUTES_MIME_TYPE = "application/cms-signed-attributes";
    /**
     * Identifying keys for Pdf view capable user agents.
     */
    public static final String[][] PDF_VIEW_USER_AGENT_KEYS = new String[][]{
        new String[]{"Mac","Safari"},
        new String[]{"Chrome"}
    };
    
    /**
     * Simple Date format "yyyy-MM-dd HH:mm:ss"
     */
    public static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    /**
     * Simple Date format "yyyy-MM-dd"
     */
    public static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    public static final String[] SHIB_ATTRIBUTE_IDs = new String[]{"Shib-Application-ID", "Shib-Session-ID", "Shib-Identity-Provider", "Shib-Authentication-Instant",
        "Shib-Authentication-Method", "Shib-AuthnContext-Class", "Shib-AuthnContext-Decl"};
    public static final String[] ATTRIBUTE_IDs = new String[]{"displayName", "cn", "initials", "sn", "givenName", "norEduPersonNIN", "personalIdentityNumber", "mail",
        "telephoneNumber", "mobileTelephoneNumber", "eppn", "persistent-id", "o", "ou", "departmentNumber", "employeeNumber", "employeeType", "title", "description",
        "affiliation", "entitlement", "street", "postOfficeBox", "postalCode", "st", "l", "preferredLanguage","country"};
    public static final String[] ID_ATTRIBUTES = new String[]{"personalIdentityNumber", "persistent-id", "norEduPersonNIN", "mail"};
    public static final String SHIB_ASSERTION_COUNT = "Shib-Assertion-Count";
    public static final String ASSERION_LOC_PREFIX = "Shib-Assertion-0";
    /**
     * Signature algorithms 
     */
    public static final String[] SIGNATURE_ALGORITHMS = new String[]{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256","http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"};
    /*
     * Levels of assurance
     */
    public static final String LOA1 = "http://id.elegnamnden.se/loa/1.0/loa1";
    public static final String LOA2 = "http://id.elegnamnden.se/loa/1.0/loa2";
    public static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";
    public static final String LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";
    
   /**
    * Default signature validation trust policy;
    */
    public static final String VALIDATION_POLICY = "All EU Trust Services";
}
