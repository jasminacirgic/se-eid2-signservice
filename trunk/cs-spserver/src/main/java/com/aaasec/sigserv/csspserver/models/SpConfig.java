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

import com.aaasec.sigserv.cscommon.config.ConfigData;

/**
 * Service provider config class with default values.
 */
public class SpConfig implements ConfigData {

    private boolean devmode;
    private String supportServiceUrl;
    private int maxMessageLength;
    private String validationServiceUrl;
    private String validationPolicy;

    @Override
    public String getName() {
        return "config";
    }

    @Override
    public void setDefaults() {
        devmode = true;
        supportServiceUrl = "http://localhost:8080/CsSpSupport/spsupport";
        maxMessageLength = 500000;
        validationServiceUrl = "http://localhost:8080/TTSigvalService/TTSigValServlet";
        validationPolicy = "All EU Trust Services";
    }

    public SpConfig() {
    }

    public boolean isDevmode() {
        return devmode;
    }

    public void setDevmode(boolean devmode) {
        this.devmode = devmode;
    }

    public String getSupportServiceUrl() {
        return supportServiceUrl;
    }

    public void setSupportServiceUrl(String supportServiceUrl) {
        this.supportServiceUrl = supportServiceUrl;
    }

    public int getMaxMessageLength() {
        return maxMessageLength;
    }

    public void setMaxMessageLength(int maxMessageLength) {
        this.maxMessageLength = maxMessageLength;
    }

    public String getValidationPolicy() {
        return validationPolicy;
    }

    public void setValidationPolicy(String validationPolicy) {
        this.validationPolicy = validationPolicy;
    }

    public String getValidationServiceUrl() {
        return validationServiceUrl;
    }

    public void setValidationServiceUrl(String validationServiceUrl) {
        this.validationServiceUrl = validationServiceUrl;
    }
}
