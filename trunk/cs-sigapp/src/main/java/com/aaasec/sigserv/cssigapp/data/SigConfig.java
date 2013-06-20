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
package com.aaasec.sigserv.cssigapp.data;

import com.aaasec.sigserv.cscommon.config.ConfigData;

/**
 * Signature service configuration data with default values.
 */
public class SigConfig implements ConfigData {

    private boolean devmode;
    private int crlValidityHours;
    private String sigServiceEntityId, sigServiceLoginUrl, signAcceptUrl;
    private String metadataCacheLocation;
    private int metadataRefreshMinutes;
    private String caCountry, caOrgName, caOrgUnitName, caSerialNumber,
            caCommonName, caFileStorageLocation,
            caDistributionUrl, signingServletUrl, signatureCaName;

    public String getName() {
        return "config";
    }

    public void setDefaults() {
        devmode = true;
        crlValidityHours = 2;
        caCountry = "SE";
        caOrgName = "TEST CA org AB (NOT A REAL ORGANIZATION)";
        caOrgUnitName = "Central Signing Service";
        caSerialNumber = "A123456-7890";
        caCommonName = "#### - EID 2.0 TEST Service";
        sigServiceEntityId = "https://eid2csig.konki.se/sign";
        sigServiceLoginUrl = "https://eid2csig.konki.se/Shibboleth.sso/Login";
        signAcceptUrl = "https://eid2csig.konki.se/signaccept/signAccept.jsp";
        caFileStorageLocation = "/Users/stefan/Sites/sigserver/";
        caDistributionUrl = "http://localhost/~stefan/sigserver/";
        signingServletUrl = "/CsSigServer/Sign";
        signatureCaName = "Central Signing CA001";
        metadataCacheLocation = "/opt/local/var/run/shibboleth/eid2-test-1.0.xml";
        metadataRefreshMinutes = 60;
    }

    public SigConfig() {
    }

    public String getCaCommonName() {
        return caCommonName;
    }

    public void setCaCommonName(String caCommonName) {
        this.caCommonName = caCommonName;
    }

    public String getCaCountry() {
        return caCountry;
    }

    public void setCaCountry(String caCountry) {
        this.caCountry = caCountry;
    }

    public String getCaDistributionUrl() {
        return caDistributionUrl;
    }

    public void setCaDistributionUrl(String caDistributionUrl) {
        this.caDistributionUrl = caDistributionUrl;
    }

    public String getCaFileStorageLocation() {
        return caFileStorageLocation;
    }

    public void setCaFileStorageLocation(String caFileStorageLocation) {
        this.caFileStorageLocation = caFileStorageLocation;
    }

    public String getCaOrgName() {
        return caOrgName;
    }

    public void setCaOrgName(String caOrgName) {
        this.caOrgName = caOrgName;
    }

    public String getCaOrgUnitName() {
        return caOrgUnitName;
    }

    public void setCaOrgUnitName(String caOrgUnitName) {
        this.caOrgUnitName = caOrgUnitName;
    }

    public String getCaSerialNumber() {
        return caSerialNumber;
    }

    public void setCaSerialNumber(String caSerialNumber) {
        this.caSerialNumber = caSerialNumber;
    }

    public int getCrlValidityHours() {
        return crlValidityHours;
    }

    public void setCrlValidityHours(int crlValidityHours) {
        this.crlValidityHours = crlValidityHours;
    }

    public boolean isDevmode() {
        return devmode;
    }

    public void setDevmode(boolean devmode) {
        this.devmode = devmode;
    }

    public String getSigServiceEntityId() {
        return sigServiceEntityId;
    }

    public void setSigServiceEntityId(String sigServiceEntityId) {
        this.sigServiceEntityId = sigServiceEntityId;
    }

    public String getSigningServletUrl() {
        return signingServletUrl;
    }

    public void setSigningServletUrl(String signingServletUrl) {
        this.signingServletUrl = signingServletUrl;
    }

    public String getSigServiceLoginUrl() {
        return sigServiceLoginUrl;
    }

    public void setSigServiceLoginUrl(String sigServiceLoginUrl) {
        this.sigServiceLoginUrl = sigServiceLoginUrl;
    }

    public String getSignatureCaName() {
        return signatureCaName;
    }

    public void setSignatureCaName(String signatureCaName) {
        this.signatureCaName = signatureCaName;
    }

    public String getSignAcceptUrl() {
        return signAcceptUrl;
    }

    public void setSignAcceptUrl(String signAcceptUrl) {
        this.signAcceptUrl = signAcceptUrl;
    }

    public String getMetadataCacheLocation() {
        return metadataCacheLocation;
    }

    public void setMetadataCacheLocation(String metadataCacheLocation) {
        this.metadataCacheLocation = metadataCacheLocation;
    }

    public int getMetadataRefreshMinutes() {
        return metadataRefreshMinutes;
    }

    public void setMetadataRefreshMinutes(int metadataRefreshMinutes) {
        this.metadataRefreshMinutes = metadataRefreshMinutes;
    }
    
}
