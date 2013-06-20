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
package com.aaasec.sigserv.csspsupport.wsdto;

import java.util.List;
import java.util.Map;

/**
 * Web service data type
 */
public class SignRequestParams {

    private String signerIdAttr;
    private String signerId;
    private String idpEntityId;
    private CertType certType;
    private SignerAuthLoa loa;
    private List<SignTaskParams> signTaskParams;
    private Map<SignRequestParams.Property, String> properties;
    private Map<String, String> parameters;

    public SignRequestParams() {
    }

    public String getSignerIdAttr() {
        return signerIdAttr;
    }

    public void setSignerIdAttr(String signerIdAttr) {
        this.signerIdAttr = signerIdAttr;
    }

    public String getSignerId() {
        return signerId;
    }

    public void setSignerId(String signerId) {
        this.signerId = signerId;
    }

    public String getIdpEntityId() {
        return idpEntityId;
    }

    public void setIdpEntityId(String idpEntityId) {
        this.idpEntityId = idpEntityId;
    }

    public List<SignTaskParams> getSignTaskParams() {
        return signTaskParams;
    }

    public void setSignTaskParams(List<SignTaskParams> signTaskParams) {
        this.signTaskParams = signTaskParams;
    }

    public Map<Property, String> getProperties() {
        return properties;
    }

    public void setProperties(Map<Property, String> properties) {
        this.properties = properties;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    public CertType getCertType() {
        return certType;
    }

    public void setCertType(CertType certType) {
        this.certType = certType;
    }

    public SignerAuthLoa getLoa() {
        return loa;
    }

    public void setLoa(SignerAuthLoa loa) {
        this.loa = loa;
    }

    public enum Property {

        returnUrl,
        requestedAlgorithm,
        signMessage,
        spEntityId,
        requestedAttributes;
    }
}
