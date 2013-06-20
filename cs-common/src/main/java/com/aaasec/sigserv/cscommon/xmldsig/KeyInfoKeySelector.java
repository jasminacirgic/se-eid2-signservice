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
package com.aaasec.sigserv.cscommon.xmldsig;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;

import java.util.logging.Logger;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

/**
 *  Key information selector
 */
public class KeyInfoKeySelector extends KeySelector implements
		KeySelectorResult {

	private static final Logger LOG = Logger.getLogger(KeyInfoKeySelector.class.getName());

	private X509Certificate certificate;

	@Override
	public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose,
			AlgorithmMethod method, XMLCryptoContext context)
			throws KeySelectorException {
//		LOG.debug("select key");
		List<XMLStructure> keyInfoContent = keyInfo.getContent();
		for (XMLStructure keyInfoStructure : keyInfoContent) {
			if (false == (keyInfoStructure instanceof X509Data)) {
				continue;
			}
			X509Data x509Data = (X509Data) keyInfoStructure;
			List<Object> x509DataList = x509Data.getContent();
			for (Object x509DataObject : x509DataList) {
				if (false == (x509DataObject instanceof X509Certificate)) {
					continue;
				}
				this.certificate = (X509Certificate) x509DataObject;
				// stop after first match
				return this;
			}
		}
		throw new KeySelectorException("No key found!");
	}

	@Override
	public Key getKey() {
		return this.certificate.getPublicKey();
	}

	public X509Certificate getCertificate() {
		return this.certificate;
	}
}
