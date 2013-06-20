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
package com.aaasec.sigserv.cssigapp.models;

import java.text.SimpleDateFormat;

/**
 * Signature server constants
 */
public interface ServerConstants {

    /**
     * The system line separator string
     */
    public static final String LF = System.getProperty("line.separator");
    /**
     * Supported ID Attributes
     */
    static final String[] SUPPORTED_ID_ATTRIBUTES = new String[]{"persistent-id", "norEduPersonNIN", "personalIdentityNumber"};
    static final String[] USER_TYPES = new String[]{"Super Admin", "Administrator", "Policy Admin","Log Admin", "", "", "", 
        "Blocked from Admin request", "Pending admin request","Guest"};

    // Admin roles
    static final int ADM_ROLE_SUPER_ADMIN = 0;
    static final int ADM_ROLE_ADMIN = 1;
    static final int ADM_ROLE_POLICY_ADMIN = 2;
    static final int ADM_ROLE_LOG_ADMIN = 3;
    // Other roles
    static final int ROLE_BLOCKED = 7;
    static final int ROLE_PENDING = 8;
    static final int ROLE_GUEST = 9;
    
    
    /**
     * Shibboleth Idp Attribute
     */
    static final String IDP_ATTRIBUTE = "Shib-Identity-Provider";
    /**
     * Simple Date format "yyyy-MM-dd HH:mm:ss"
     */
    static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    /**
     * Simple Date format "yyyy-MM-dd"
     */
    static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    /**
     * Signature status
     */
    static final String SIGNSTATUS_VERIFIED = "verified";
    static final String SIGNSTATUS_INVALID = "invalid";
    static final String SIGNSTATUS_SYNTAX = "syntax";
    static final String SIGNSTATUS_ABSENT = "absent";
    static final String SIGNSTATUS_UNVERIFIABLE = "unverifiable";
    static final String SIGNSTATUS_INVALID_LOTL = "invalidLotL";
    /**
     * Generic constants
     */
    static final long HOUR_MILLIS = 1000*60*60;
    static final long DAY_MILLIS = HOUR_MILLIS*24;
}
