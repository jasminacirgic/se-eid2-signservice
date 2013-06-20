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

import java.util.Map;

/**
 * Web service data type
 */
public class SignTaskParams {

    private String signTaskId;
    private byte[] tbsDocument;
    private AdesType adesType;
    private SigType sigType;
    private String policy;
    private Map<String, String> parameters;

    public SignTaskParams() {
    }

    public String getSignTaskId() {
        return signTaskId;
    }

    public void setSignTaskId(String signTaskId) {
        this.signTaskId = signTaskId;
    }

    public byte[] getTbsDocument() {
        return tbsDocument;
    }

    public void setTbsDocument(byte[] tbsDocument) {
        this.tbsDocument = tbsDocument;
    }

    public AdesType getAdesType() {
        return adesType;
    }

    public void setAdesType(AdesType adesType) {
        this.adesType = adesType;
    }

    public SigType getSigType() {
        return sigType;
    }

    public void setSigType(SigType sigType) {
        this.sigType = sigType;
    }

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }
}
