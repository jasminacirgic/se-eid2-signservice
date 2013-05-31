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
package com.aaasec.sigserv.csspsupport.sigrequest;

import com.aaasec.sigserv.cscommon.Constants;
import static com.aaasec.sigserv.cscommon.Constants.LOA3;
import com.aaasec.sigserv.cscommon.SigAlgorithms;
import com.aaasec.sigserv.cscommon.marshaller.XmlBeansUtil;
import com.aaasec.sigserv.cscommon.xmldsig.XMLSign;
import com.aaasec.sigserv.csspapp.models.SignSession;
import com.aaasec.sigserv.csspsupport.models.AttrMapConfig.MapAttributes;
import com.aaasec.sigserv.csspsupport.models.AttrMapConfig.MapAttributes.SAMLAttrName;
import com.aaasec.sigserv.csspsupport.models.SupportConfig;
import com.aaasec.sigserv.csspsupport.models.SupportModel;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;
import org.w3c.dom.Node;
import se.elegnamnden.id.csig.x10.dssExt.ns.CertRequestPropertiesType;
import se.elegnamnden.id.csig.x10.dssExt.ns.CertRequestPropertiesType.CertType;
import se.elegnamnden.id.csig.x10.dssExt.ns.MappedAttributeType;
import se.elegnamnden.id.csig.x10.dssExt.ns.MappedAttributeType.CertNameType;
import se.elegnamnden.id.csig.x10.dssExt.ns.PreferredSAMLAttributeNameType;
import se.elegnamnden.id.csig.x10.dssExt.ns.RequestedAttributesType;
import se.elegnamnden.id.csig.x10.dssExt.ns.SignRequestExtensionType;
import se.elegnamnden.id.csig.x10.dssExt.ns.SignTaskDataType;
import se.elegnamnden.id.csig.x10.dssExt.ns.SignTaskDataType.AdESType;
import se.elegnamnden.id.csig.x10.dssExt.ns.SignTaskDataType.SigType;
import x0Assertion.oasisNamesTcSAML2.AttributeType;
import x0Assertion.oasisNamesTcSAML2.ConditionsType;
import x0Assertion.oasisNamesTcSAML2.NameIDType;
import x0CoreSchema.oasisNamesTcDss1.Eid2ReqAnyType;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument.SignRequest;

/**
 * Functions for generation of sign requests.
 */
public class SigRequest implements Constants {

    private static final String ENTITY_ID_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

    public static byte[] getRequest(SupportModel model, SignSession session) {
        SignRequestDocument sigRequestDoc = SignRequestDocument.Factory.newInstance();
        SignRequest sigRequest = sigRequestDoc.addNewSignRequest();
        //Set the request values
        getRequestData(sigRequest, model, session);
        Node sigParent = getRequestSignatureParent(sigRequest);
        // Generate unsigned request XML with marshaller
        byte[] unsignedReqXML = XmlBeansUtil.getStyledBytes(sigRequestDoc);
        // Sign request
        byte[] signedReqXML;
        signedReqXML = XMLSign.getSignedXML(unsignedReqXML, model.getPrivateKey(), model.getCert(), sigParent).sigDocBytes;

        return signedReqXML;
    }

    public static void getRequestData(SignRequest sigRequest, SupportModel model, SignSession session) {
        SupportConfig conf = (SupportConfig) model.getConf();
        String returnUrl = (session.getReturnUrl().length() == 0) ? model.getSpServiceReturnUrl() : session.getReturnUrl();
        String spEntityId = (session.getSpEntityId().length() == 0) ? model.getSpEntityId() : session.getSpEntityId();
        long currentTimeLong = System.currentTimeMillis();
        long expiry = currentTimeLong + 20 * 60 * 1000;
        Calendar currentTime = Calendar.getInstance();
        Calendar expiryTime = Calendar.getInstance();
        expiryTime.setTime(new Date(expiry));
        //Create Eid2 req extension
        SignRequestExtensionType eid2Request = sigRequest.addNewOptionalInputs().addNewSignRequestExtension();


        sigRequest.setProfile(PROTOCOL_BINDING);
        sigRequest.setRequestID(session.getSignRequestID());
        eid2Request.setRequestTime(Calendar.getInstance());
        if (session.getSignMessage() != null && session.getSignMessage().length > 0) {
            eid2Request.setSignMessage(session.getSignMessage());
        }
        eid2Request.setSignRequester(getEntityNameID(ENTITY_ID_FORMAT, spEntityId));
        eid2Request.setSignService(getEntityNameID(ENTITY_ID_FORMAT, model.getSigServiceEntityId()));
        ConditionsType conditions = eid2Request.addNewConditions();
        conditions.setNotBefore(currentTime);
        conditions.setNotOnOrAfter(expiryTime);
        conditions.addNewAudienceRestriction().addAudience(returnUrl);
        //Set Signer information
        AttributeType signerAttr = eid2Request.addNewSigner().addNewAttribute();
        XmlObject signerAttrVal = signerAttr.addNewAttributeValue();
        XmlString idString = XmlString.Factory.newInstance();
        idString.setStringValue(session.getSignerId());
        signerAttrVal.set(idString);
        signerAttr.setName("urn:oid:" + session.getSignerAttribute());
        //Set requested signer attributes:
        CertRequestPropertiesType certReqProp = eid2Request.addNewCertRequestProperties();

        //Set certType
        CertType.Enum certType = getCertType(conf.getCertType(), session.getCertType());
        if (certType != null) {
            certReqProp.setCertType(certType);
        }
        RequestedAttributesType requestedAttributes = certReqProp.addNewRequestedCertAttributes();
        setRequestedAttributes(requestedAttributes, model.getAttrMapConf().getAttrMap());

        //Set requested LoA
        if (session.getSignerAuthLoa() != null) {
            certReqProp.setAuthnContextClassRef(session.getSignerAuthLoa());
        } else {
            if (conf.getLoa() == null) {
                certReqProp.setAuthnContextClassRef(LOA3);
            } else {
                certReqProp.setAuthnContextClassRef(conf.getLoa());
            }
        }

        eid2Request.setIdentityProvider(getEntityNameID(ENTITY_ID_FORMAT, session.getIdpEntityId()));
        // Use new session tools for processing document.

        //Set Sign Algo;
        SigAlgorithms sigAlgo;
        if (session.getReqSigAlgorithm().length() < 4) {
            sigAlgo = SigAlgorithms.getAlgoByURI(conf.getSigAlgo());
        } else {
            sigAlgo = SigAlgorithms.getAlgoByURI(session.getReqSigAlgorithm());
        }
        switch (session.getDocumentType()) {
            case PDF:
                // If this is a PDF to be signed, the ECDSA is not supported.
                if (sigAlgo == null || sigAlgo.equals(SigAlgorithms.ECDSA)) {
                    session.setReqSigAlgorithm(XMLSign.RSA_SHA256);
                    sigAlgo = SigAlgorithms.RSA;
                }
        }
        session.setReqSigAlgorithm(sigAlgo.getSigAlgo());
        eid2Request.setRequestedSignatureAlgorithm(session.getReqSigAlgorithm());
        boolean presignSuccess = session.presignDocument(model.getPreSignKeyPair(sigAlgo).getPrivate(), model.getPreSignCert(sigAlgo), sigAlgo.getDigestAlgo(), sigAlgo.getSigAlgo());
        if (presignSuccess) {
//            String hashAlgorithm = session.getHashAlgorithm();
            /*
             * Set the octets to be checked, hashed and signed by the signature server.
             */
            SignTaskDataType signedInfoInp = sigRequest.addNewInputDocuments().addNewOther().addNewSignTasks().addNewSignTaskData();
            signedInfoInp.setToBeSignedBytes(session.getTransformData());
            signedInfoInp.setAdESType(AdESType.NONE);
            switch (session.getDocumentType()) {
                case PDF:
                    signedInfoInp.setSigType(SigType.PDF);
                    break;
                default:
                    signedInfoInp.setSigType(SigType.XML);
            }
        }
    }

    private static NameIDType getEntityNameID(String format, String value) {
        NameIDType entity = NameIDType.Factory.newInstance();
        entity.setFormat(format);
        entity.setStringValue(value);
        return entity;
    }

    private static Node getRequestSignatureParent(SignRequest sigReq) {
        Eid2ReqAnyType optionalInputs = sigReq.getOptionalInputs();
        if (optionalInputs == null) {
            optionalInputs = sigReq.addNewOptionalInputs();
        }
        return optionalInputs.getDomNode();
    }

    private static void setRequestedAttributes(RequestedAttributesType requestedAttributes, Map<String, MapAttributes> attrMap) {
        Set<String> keySet = attrMap.keySet();
        for (String key : keySet) {
            try {
                MapAttributes samlAtr = attrMap.get(key);
                String[] attrParams = key.split(":");
                // Get certNameType
                CertNameType.Enum certNameType = CertNameType.RDN;
                try {
                    certNameType = CertNameType.Enum.forString(attrParams[0]);
                } catch (Exception ex) {
                }


                MappedAttributeType reqAttr = requestedAttributes.addNewRequestedCertAttribute();
                reqAttr.setCertAttributeRef(attrParams[1]);
                reqAttr.setCertNameType(certNameType);
                reqAttr.setRequired(samlAtr.required);
                if (samlAtr.friendlyName != null) {
                    reqAttr.setFriendlyName(samlAtr.friendlyName);
                }
                if (samlAtr.defaultValue != null) {
                    reqAttr.setDefaultValue(samlAtr.defaultValue);
                }
                if (samlAtr.samlAttributeNames.size() > 0) {
                    for (SAMLAttrName samlAtrName : samlAtr.samlAttributeNames) {
                        PreferredSAMLAttributeNameType newSamlAttributeName = reqAttr.addNewSamlAttributeName();
                        newSamlAttributeName.setStringValue(samlAtrName.name);
                        if (samlAtr.samlAttributeNames.size() > 1) {
                            newSamlAttributeName.setOrder(samlAtrName.order);
                        }
                    }
                }
            } catch (Exception ex) {
            }
        }
    }

    private static CertType.Enum getCertType(String confCertTypeStr, String reqCertTypeString) {
        CertType.Enum certType;

        try {
            com.aaasec.sigserv.csspsupport.wsdto.CertType reqCertType = com.aaasec.sigserv.csspsupport.wsdto.CertType.valueOf(reqCertTypeString);
            switch (reqCertType){
                case PKC:
                    certType = CertType.PKC;
                    break;
                case QC:
                    certType = CertType.QC;
                    break;
                case QC_SSCD:
                    certType = CertType.QC_SSCD;
                    break;
                default:
                    certType = CertType.PKC;                
            }
            return certType;
        } catch (Exception ex) {
        }

        try {
            certType = CertType.Enum.forString(confCertTypeStr);
            return certType;
        } catch (Exception ex) {
        }
        return null;
    }
}
