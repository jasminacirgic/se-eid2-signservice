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
public class SignTaskResult {

    private Status status;
    private String signTaskId;
    private byte[] signedDoc;
    private String signedDocRef;
    private Map<String,String> parameters;

    public SignTaskResult() {
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public String getSignTaskId() {
        return signTaskId;
    }

    public void setSignTaskId(String signTaskId) {
        this.signTaskId = signTaskId;
    }

    public byte[] getSignedDoc() {
        return signedDoc;
    }

    public void setSignedDoc(byte[] signedDoc) {
        this.signedDoc = signedDoc;
    }

    public String getSignedDocRef() {
        return signedDocRef;
    }

    public void setSignedDocRef(String signedDocRef) {
        this.signedDocRef = signedDocRef;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

}
