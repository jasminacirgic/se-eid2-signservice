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

import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.EntityKeyStore;
import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.PEM;
import com.aaasec.sigserv.cscommon.SigAlgorithms;
import com.aaasec.sigserv.cscommon.config.ConfigData;
import com.aaasec.sigserv.cscommon.config.ConfigFactory;
import com.google.gson.Gson;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Model for the support web service.
 */
public final class SupportModel implements Constants {

    private Gson gson = new Gson();
    private String dataDir;
    private EntityKeyStore entityKeyStore;
    private EntityKeyStore testEntityKeyStore;
    private String entityIdPemCert;
    private SupportConfig conf;
    private AttrMapConfig attrMapConf;
//    private KeyStore sPkeyStore;    
    private final String sigServiceEntityId;
    private final String sigServiceRequestUrl;
    private final String spEntityId;
    private final String spServiceReturnUrl;
    private static KeyPair rsaPresignKeys, ecdsaPresignKeys;
    private X509Certificate rsaPresignCert, ecdsaPresignCert;

    static {
        try {
            KeyPair rsakp = generateRSAKeyPair();
            KeyPair ecdsakp = generateECDSAKeyPair();
            rsaPresignKeys = rsakp;
            ecdsaPresignKeys = ecdsakp;
        } catch (Exception ex) {
            Logger.getLogger(SupportModel.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public SupportModel(String dataDir) {
        this.dataDir = dataDir;
        ConfigFactory<SupportConfig> confFact = new ConfigFactory<SupportConfig>(dataDir, new SupportConfig());
        conf = confFact.getConfData();
        ConfigFactory<AttrMapConfig> attrConfFact = new ConfigFactory<AttrMapConfig>(dataDir, new AttrMapConfig());
        attrMapConf = attrConfFact.getConfData();
        sigServiceEntityId = conf.getSigServiceEntityId();
        sigServiceRequestUrl = conf.getSigServiceRequestUrl();
        spEntityId = conf.getSpEntityId();
        spServiceReturnUrl = conf.getSpServiceReturnUrl();

        initKeyStore();
        try {
            entityIdPemCert = PEM.getPemCert(getCert().getEncoded());
            File spCertFile = new File(FileOps.getfileNameString(dataDir, "conf"), "spCert.crt");
            FileOps.saveTxtFile(spCertFile, entityIdPemCert);
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(SupportModel.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void initKeyStore() {
        String keyStoreDir = FileOps.getfileNameString(dataDir, "keyStores");
        entityKeyStore = new EntityKeyStore(conf.getSpEntityId(), keyStoreDir, "12#9ijlsder%&/7129ooplskt".toCharArray());
        // get testEntityKeyStore
        testEntityKeyStore = new EntityKeyStore("testId", keyStoreDir, "12#thurtu7/&5t%oplskt".toCharArray());
    }

    public KeyPair getPreSignKeyPair(SigAlgorithms sigAlgo) {
        switch (sigAlgo) {
            case ECDSA:
                return ecdsaPresignKeys;
            default:
                return rsaPresignKeys;
        }
    }

    public X509Certificate getPreSignCert(SigAlgorithms sigAlgo) {
        switch (sigAlgo) {
            case ECDSA:
                if (ecdsaPresignCert == null) {
                    try {
                        ecdsaPresignCert = generateV1Certificate("presigner", ecdsaPresignKeys, SigAlgorithms.ECDSA);
                    } catch (Exception ex) {
                        Logger.getLogger(SupportModel.class.getName()).log(Level.SEVERE, null, ex);
                    } 
                }
                return ecdsaPresignCert;
            default:
                if (rsaPresignCert == null) {
                    try {
                        rsaPresignCert = generateV1Certificate("presigner", rsaPresignKeys, SigAlgorithms.RSA);
                    } catch (Exception ex) {
                        Logger.getLogger(SupportModel.class.getName()).log(Level.SEVERE, null, ex);
                    } 
                }
                return rsaPresignCert;
        }
    }

    private static KeyPair generateRSAKeyPair()
            throws NoSuchAlgorithmException {

        KeyPair kp = null;
        KeyPairGenerator generator;
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        kp = generator.generateKeyPair();
        return kp;
    }

    private static KeyPair generateECDSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("P-256");

        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider());
        g.initialize(ecSpec, new SecureRandom());
        KeyPair pair = g.generateKeyPair();
        return pair;
    }

    public static X509Certificate generateV1Certificate(String subject, KeyPair pair, SigAlgorithms algorithm) throws OperatorCreationException, IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {

        BigInteger certSerial = BigInteger.valueOf(System.currentTimeMillis());
        X500Name issuerDN = new X500Name("CN=" + subject);
        X500Name subjectDN = new X500Name("CN=" + subject);
        Date notBefore = new Date(System.currentTimeMillis() - 10000);
        Date notAfter = new Date(System.currentTimeMillis() + 10000);
        PublicKey pubKey = (pair.getPublic());
        X509v1CertificateBuilder certGen = new JcaX509v1CertificateBuilder(issuerDN, certSerial, notBefore, notAfter, subjectDN, pubKey);

        ContentSigner signer = new JcaContentSignerBuilder(algorithm.getDummyCertAlgo()).build(pair.getPrivate());
        byte[] encoded = certGen.build(signer).getEncoded();
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        InputStream is = new ByteArrayInputStream(encoded);
        X509Certificate generateCertificate = (X509Certificate) fact.generateCertificate(is);
        is.close();

        String certStr = generateCertificate.toString();
//        strb.append("Certificate:\n").append(certStr).append("\n");

        return generateCertificate;
    }

    public PrivateKey getPrivateKey() {
        return entityKeyStore.getPrivate();
    }

    public X509Certificate getCert() {
        return entityKeyStore.getKsCert();
    }

    public PrivateKey getTestPrivateKey() {
        return testEntityKeyStore.getPrivate();
    }

    public X509Certificate getTestCert() {
        return testEntityKeyStore.getKsCert();
    }

    public Gson getGson() {
        return gson;
    }

    public void setGson(Gson gson) {
        this.gson = gson;
    }

    public String getDataDir() {
        return dataDir;
    }

    public ConfigData getConf() {
        return conf;
    }

    public String getSigServiceEntityId() {
        return sigServiceEntityId;
    }

    public String getSigServiceRequestUrl() {
        return sigServiceRequestUrl;
    }

    public String getSpEntityId() {
        return spEntityId;
    }

    public String getSpServiceReturnUrl() {
        return spServiceReturnUrl;
    }

    public AttrMapConfig getAttrMapConf() {
        return attrMapConf;
    }
}
