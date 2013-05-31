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

/**
 * Web service data type
 */
public class Status {

    private int statusGroup;
    private String statusGroupDescription;
    private int statusCode;
    private String statusCodeDescription;

    public Status() {
    }

    public int getStatusGroup() {
        return statusGroup;
    }

    public void setStatusGroup(int statusGroup) {
        this.statusGroup = statusGroup;
    }

    public String getStatusGroupDescription() {
        return statusGroupDescription;
    }

    public void setStatusGroupDescription(String statusGroupDescription) {
        this.statusGroupDescription = statusGroupDescription;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getStatusCodeDescription() {
        return statusCodeDescription;
    }

    public void setStatusCodeDescription(String statusCodeDescription) {
        this.statusCodeDescription = statusCodeDescription;
    }
}
