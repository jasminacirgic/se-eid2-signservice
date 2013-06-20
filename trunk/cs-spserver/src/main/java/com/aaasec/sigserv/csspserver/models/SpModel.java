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
package com.aaasec.sigserv.csspserver.models;

import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.OSValidator;
import com.aaasec.sigserv.cscommon.config.ConfigFactory;
import com.google.gson.Gson;

/**
 * Service provider web application model.
 */
public final class SpModel implements Constants {

    private static final Gson gson = new Gson();
    private static final String dataDir, docDir;
    private static final boolean devmode;
    private static final SpConfig conf;

    static {
        String osPath = (OSValidator.isMac()) ? MAC_PATH : WIN_PATH;
        dataDir = FileOps.getfileNameString(osPath, SP_FOLDER_NAME);
        docDir = FileOps.getfileNameString(dataDir, "spdocs");
        FileOps.createDir(docDir);
        ConfigFactory<SpConfig> confFact = new ConfigFactory<SpConfig>(dataDir, new SpConfig());
        conf = confFact.getConfData();
        devmode = conf.isDevmode();

    }

    private SpModel(){        
    }
    
    public static Gson getGson() {
        return gson;
    }

    public static String getDataDir() {
        return dataDir;
    }

    public static String getDocDir() {
        return docDir;
    }

    public static boolean isDevmode() {
        return devmode;
    }

    public static SpConfig getConf() {
        return conf;
    }

}
