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
package com.aaasec.sigserv.csspsupport.models;

import com.aaasec.sigserv.cscommon.config.ConfigData;

/**
 * Configuration data class for the support service with default values.
 */
public class SupportConfig implements ConfigData {

    private String spEntityId, spServiceReturnUrl, sigServiceEntityId, sigServiceRequestUrl, validationServiceUrl, certType, sigAlgo, loa;

    @Override
    public String getName() {
        return "spSupportConfig";
    }

    @Override
    public void setDefaults() {
        spEntityId = "https://eid2cssp.3xasecurity.com/sign";
        spServiceReturnUrl = "/CSspServer/SpServlet";
        sigServiceEntityId = "https://eid2csig.konki.se/sign";
        sigServiceRequestUrl = "/CsSigServer/SigRequest";
        validationServiceUrl = "https://tsltrust.3xasecurity.com/sigval/TTSigValServlet";
        certType = "QC/SSCD";
        sigAlgo = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        loa = "http://id.elegnamnden.se/loa/1.0/loa3";
    }

    public SupportConfig() {
    }

    public String getSigServiceEntityId() {
        return sigServiceEntityId;
    }

    public void setSigServiceEntityId(String sigServiceEntityId) {
        this.sigServiceEntityId = sigServiceEntityId;
    }

    public String getSigServiceRequestUrl() {
        return sigServiceRequestUrl;
    }

    public void setSigServiceRequestUrl(String sigServiceRequestUrl) {
        this.sigServiceRequestUrl = sigServiceRequestUrl;
    }

    public String getSpEntityId() {
        return spEntityId;
    }

    public void setSpEntityId(String spEntityId) {
        this.spEntityId = spEntityId;
    }

    public String getSpServiceReturnUrl() {
        return spServiceReturnUrl;
    }

    public void setSpServiceReturnUrl(String spServiceReturnUrl) {
        this.spServiceReturnUrl = spServiceReturnUrl;
    }

    public String getCertType() {
        return certType;
    }

    public void setCertType(String certType) {
        this.certType = certType;
    }

    public String getSigAlgo() {
        return sigAlgo;
    }

    public void setSigAlgo(String sigAlgo) {
        this.sigAlgo = sigAlgo;
    }

    public String getLoa() {
        return loa;
    }

    public void setLoa(String loa) {
        this.loa = loa;
    }

    public String getValidationServiceUrl() {
        return validationServiceUrl;
    }

    public void setValidationServiceUrl(String validationServiceUrl) {
        this.validationServiceUrl = validationServiceUrl;
    }
    
}
