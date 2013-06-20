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

import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.csspapp.SignSupportAPI;
import com.aaasec.sigserv.csspapp.models.SignSession;
import com.aaasec.sigserv.csspsupport.models.SupportConfig;
import com.aaasec.sigserv.csspsupport.models.SupportModel;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Web application lifecycle listener.
 */
@WebListener()
public class SpSupportContextListener implements ServletContextListener {

    static boolean initialized = false;

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        ServletContext servletContext = sce.getServletContext();
        String contextPath = servletContext.getContextPath();
        if (contextPath != null && !initialized) {
            try {
                Security.removeProvider("BC");
            } catch (Exception ex) {
            }
            int insertProviderAt = Security.addProvider(new BouncyCastleProvider());
            SpSuppContextParams.setDataDir(getParam("DataDir", servletContext));
            SpSuppContextParams.setSignTaskMap(new HashMap<String, SignSession>());

            SupportModel model = new SupportModel(SpSuppContextParams.getDataDir());
            SupportConfig conf = (SupportConfig) model.getConf();
            String sigTempDir = FileOps.getfileNameString(model.getDataDir(), "sigTemp");

            SpSuppContextParams.setConf(conf);
            SpSuppContextParams.setModel(model);
            SpSuppContextParams.setSigTempDir(sigTempDir);
            SpSuppContextParams.setSignSessionMaxAge(getMaxAge(getParam("SignSessionMaxAge", servletContext)));

            SignSupportAPI.setValidationServiceUrl(conf.getValidationServiceUrl());
            SignSupportAPI.setTempFileLocation(sigTempDir);
            initialized = true;
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        initialized = false;
    }

    private static String getParam(String paramName, ServletContext sc) {
        String value = sc.getInitParameter(paramName);
        if (value != null && value.length() > 0) {
            return value;
        }
        return "";
    }

    private long getMaxAge(String param) {
        try {
            long maxSessionMinutes = Long.parseLong(param);
            maxSessionMinutes = (maxSessionMinutes * 1000 * 60);
            return maxSessionMinutes;
        } catch (Exception ex) {
            return 1000 * 60 * 10;
        }
    }
}
