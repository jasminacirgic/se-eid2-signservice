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
package com.aaasec.sigserv.csspapp.models;

import com.aaasec.sigserv.cscommon.enums.Enums;
import java.util.ArrayList;
import java.util.List;

/**
 * Service status data class.
 */
    public class ServiceStatus{
        public String status = "init";
        public String signTaskID="";
        public String documentName="";
        public boolean respSigValid=false;
        public boolean signedDocValid=false;
        public boolean validResponse=false;
        public String responseCode ="";
        public String responseMessage="";
        public String signingTime="";
        public List<IdAttribute> userId = new ArrayList<IdAttribute>();
        public int pathLen=0;

        public ServiceStatus() {
        }
        
        public ServiceStatus setInitStatus(){
            status="init";
            documentName="";
            respSigValid=false;
            validResponse=false;
            signedDocValid=false;
            responseCode="";
            responseMessage="";
            signingTime="";
            userId = new ArrayList<IdAttribute>();
            return this;
        }
                
        public ServiceStatus setSigAcceptStatus(String fileName){
            status="accept";
            this.documentName=fileName;
            respSigValid=false;
            validResponse=false;
            signedDocValid=false;
            responseCode="";
            responseMessage="";
            signingTime="";
            userId = new ArrayList<IdAttribute>();
            return this;
        }
                
        public ServiceStatus setResponseStatus(){
            status="response";
            respSigValid=false;
            validResponse=false;
            signedDocValid=false;
            responseCode="";
            responseMessage="";
            signingTime="";
            userId = new ArrayList<IdAttribute>();
            return this;
        }
        
        public void addUserAttr(String name, String value){
            userId.add(new IdAttribute(name, value));
        }
        
        public void setStatusCode(Enums.ResponseCodeMajor code){
            responseCode = code.getCode();
            responseMessage = code.getMessage();
        }
    }
    
    
