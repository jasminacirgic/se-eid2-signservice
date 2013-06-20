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
public class SignatureResult {

    private String transactionId;
    private Status status;
    private List<SignTaskResult> signTaskResult;
    private Map<String, String> signerId;
    private Map<String, String> parameters;

    public SignatureResult() {
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public List<SignTaskResult> getSignTaskResult() {
        return signTaskResult;
    }

    public void setSignTaskResult(List<SignTaskResult> signTaskResult) {
        this.signTaskResult = signTaskResult;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public Map<String, String> getSignerId() {
        return signerId;
    }

    public void setSignerId(Map<String, String> signerId) {
        this.signerId = signerId;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

}
