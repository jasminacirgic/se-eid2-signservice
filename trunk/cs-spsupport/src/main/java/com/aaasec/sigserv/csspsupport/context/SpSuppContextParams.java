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
package com.aaasec.sigserv.csspsupport.context;

import com.aaasec.sigserv.csspapp.models.SignSession;
import com.aaasec.sigserv.csspsupport.models.SupportConfig;
import com.aaasec.sigserv.csspsupport.models.SupportModel;
import java.util.Map;

/**
 * Context parameters for the support service.
 */
public class SpSuppContextParams {

    private static String dataDir = "";
    private static SupportConfig conf;
    private static SupportModel model;
    private static Map<String, SignSession> signTaskMap;
    private static long signSessionMaxAge;
    private static String sigTempDir;

    private SpSuppContextParams() {
    }

    public static String getDataDir() {
        return dataDir;
    }

    public static void setDataDir(String dataDir) {
        SpSuppContextParams.dataDir = dataDir;
    }

    public static SupportConfig getConf() {
        return conf;
    }

    public static void setConf(SupportConfig conf) {
        SpSuppContextParams.conf = conf;
    }

    public static SupportModel getModel() {
        return model;
    }

    public static void setModel(SupportModel model) {
        SpSuppContextParams.model = model;
    }

    public static Map<String, SignSession> getSignTaskMap() {
        return signTaskMap;
    }

    public static void setSignTaskMap(Map<String, SignSession> signTaskMap) {
        SpSuppContextParams.signTaskMap = signTaskMap;
    }

    public static String getSigTempDir() {
        return sigTempDir;
    }

    public static void setSigTempDir(String sigTempDir) {
        SpSuppContextParams.sigTempDir = sigTempDir;
    }

    public static long getSignSessionMaxAge() {
        return signSessionMaxAge;
    }

    public static void setSignSessionMaxAge(long signSessionMaxAge) {
        SpSuppContextParams.signSessionMaxAge = signSessionMaxAge;
    }
}
