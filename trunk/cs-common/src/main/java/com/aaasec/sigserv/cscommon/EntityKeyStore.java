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
package com.aaasec.sigserv.cscommon;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
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
 * Creates key store with a simple self signed cert
 */
public class EntityKeyStore {

    private static final Logger LOG = Logger.getLogger(EntityKeyStore.class.getName());
    private KeyStore key_store;
    private File keyStoreFile;
    private static final int KEYLENGTH = 2048;
    private final static String ROOT = "ROOT_CA";
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private String subject;
    private String entityID;
    private char[] KS_PASSWORD;
    private boolean initialized;

    /**
     * Initiates an entity key store with a generated self signed certificate
     * @param entityName The name of the entity represented by this key store
     * @param keystoreDir The directory where the key store is stored.
     * @param psPass the key store password
     */
    public EntityKeyStore(String entityName, String keystoreDir, char[] ksPass) {
        this.subject = entityName;
        this.KS_PASSWORD = ksPass;
        initialized = false;
        entityID = FnvHash.getFNV1aToHex(subject);
        keyStoreFile = new File(keystoreDir, entityID + ".keystore");
        keyStoreFile.getParentFile().mkdirs();
        LOG.info("New keystore generated at: " + keyStoreFile.getAbsolutePath());

        if (!keyStoreFile.canRead()) {
            createKeyStore(keyStoreFile);
        }
        initKeyStore();
    }

    private void createKeyStore(File keyStoreFile) {
        try {
            key_store = KeyStore.getInstance("JKS");
            key_store.load(null, null);
            KeyPair kp = generateKeyPair("RSA", KEYLENGTH);
            generateV1Certificate(kp);
            saveKeyStore();
            LOG.info("New keystore created for entity:" + subject);
        } catch (Exception ex) {
            LOG.log(Level.WARNING, null, ex);
        }
    }

    private void initKeyStore() {
        try {
            if (keyStoreFile.canRead()) {
                key_store = KeyStore.getInstance("JKS");
                key_store.load(new FileInputStream(keyStoreFile), KS_PASSWORD);
                Certificate root = key_store.getCertificate(ROOT);
                if (root != null) {
                    initialized = true;
                }
            }
        } catch (Exception ex) {
            LOG.log(Level.WARNING, null, ex);
        }
    }

    public KeyStore getKeyStore() {
        if (initialized) {
            return key_store;
        }
        return null;
    }

    public PrivateKey getPrivate() {
        if (initialized) {
            try {
                return (PrivateKey)key_store.getKey(ROOT, KS_PASSWORD);
            } catch (KeyStoreException ex) {
                Logger.getLogger(EntityKeyStore.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(EntityKeyStore.class.getName()).log(Level.SEVERE, null, ex);
            } catch (UnrecoverableKeyException ex) {
                Logger.getLogger(EntityKeyStore.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }

    public boolean isInitialized() {
        return initialized;
    }

    public X509Certificate getKsCert() {
        if (initialized) {
            try {
                Certificate certificate = key_store.getCertificate(ROOT);
                return getCert(certificate);
            } catch (KeyStoreException ex) {
                Logger.getLogger(EntityKeyStore.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }

    /**
     * Generate a KeyPair using the specified algorithm with the given size.
     *
     * @param algorithm the algorithm to use
     * @param bits the length of the key (modulus) in bits
     *
     * @return the KeyPair
     *
     * @exception NoSuchAlgorithmException if no KeyPairGenerator is available for
     *                                     the requested algorithm
     */
    private KeyPair generateKeyPair(String algorithm, int bits)
            throws NoSuchAlgorithmException {

        KeyPair kp = null;
        KeyPairGenerator generator = null;
        generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(bits);
        kp = generator.generateKeyPair();
        return kp;
    }

    public X509Certificate generateV1Certificate(KeyPair pair) throws OperatorCreationException, IOException, CertificateException, KeyStoreException {

        BigInteger certSerial = BigInteger.valueOf(System.currentTimeMillis());
        X500Name issuerDN = new X500Name("CN=" + subject);
        X500Name subjectDN = new X500Name("CN=" + subject);
        Calendar startTime = Calendar.getInstance();
        startTime.setTime(new Date());
        startTime.add(Calendar.HOUR, -2);
        Calendar expiryTime = Calendar.getInstance();
        expiryTime.setTime(new Date());
        expiryTime.add(Calendar.YEAR, 10);
        Date notBefore = startTime.getTime();
        Date notAfter = expiryTime.getTime();
        PublicKey pubKey = (pair.getPublic());
        X509v1CertificateBuilder certGen = new JcaX509v1CertificateBuilder(issuerDN, certSerial, notBefore, notAfter, subjectDN, pubKey);

        ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").build(pair.getPrivate());
        byte[] encoded = certGen.build(signer).getEncoded();
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        InputStream is = new ByteArrayInputStream(encoded);
        X509Certificate generateCertificate = (X509Certificate) fact.generateCertificate(is);
        is.close();

        // set the CA cert as trusted root
        X509Certificate[] chain = new X509Certificate[]{generateCertificate};
        addToKeyStore(pair, chain, ROOT);

        String certStr = generateCertificate.toString();

        return generateCertificate;
    }

    /**
     * Add the private key and the certificate chain to the key store.
     */
    public void addToKeyStore(KeyPair keyPair, X509Certificate[] chain, String alias) throws KeyStoreException {
        key_store.setKeyEntry(alias, keyPair.getPrivate(), KS_PASSWORD, chain);
    }

    private void saveKeyStore() {
        try {
            // write the KeyStore to disk
            FileOutputStream os = new FileOutputStream(keyStoreFile);
            key_store.store(os, KS_PASSWORD);
            os.close();
        } catch (Exception ex) {
            LOG.warning("Error saving KeyStore! " + ex.getMessage());
        }
    }

    public static X509Certificate getCert(Certificate inCert) {
        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            InputStream is = new ByteArrayInputStream(inCert.getEncoded());
            X509Certificate generateCertificate = (X509Certificate) fact.generateCertificate(is);
            is.close();
            return generateCertificate;
        } catch (IOException ex) {
            Logger.getLogger(EntityKeyStore.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(EntityKeyStore.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
