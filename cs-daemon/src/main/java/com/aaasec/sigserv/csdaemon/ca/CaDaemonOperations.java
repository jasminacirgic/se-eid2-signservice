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
package com.aaasec.sigserv.csdaemon.ca;

import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.ObserverConstants;
import com.aaasec.sigserv.cscommon.PEM;
import com.aaasec.sigserv.csdaemon.Console;
import com.aaasec.sigserv.csdaemon.DaemonModel;
import com.aaasec.sigserv.cssigapp.ca.CertPath;
import com.aaasec.sigserv.cssigapp.ca.CertificationAuthority;
import iaik.x509.X509Certificate;
import java.io.File;
import java.security.cert.CertificateEncodingException;
import java.util.Observable;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JProgressBar;

/**
 * Operations performed by the CA Daemon application.
 */
public class CaDaemonOperations extends Observable implements Runnable, ObserverConstants {

    private static final Logger LOG = Logger.getLogger(CaDaemonOperations.class.getName());
    private static final String[] EVENT = new String[]{Console.GRAY, Console.ORANGE, Console.NORMAL};
    private static final String[] ACTION = new String[]{Console.GRAY, Console.ATTRIBUTE, Console.NORMAL};
    private static final String[] HEAD = new String[]{Console.MAGENTA, Console.GREEN_BOLD, Console.NORMAL};
    private final DaemonModel model;
    private final JProgressBar pBar;
    private Console con;

    /**
     * Constructor
     * @param model TSL Trust application model data 
     * @param pBar progress bar
     * @param con The console frame for displaying progress data
     */
    public CaDaemonOperations(DaemonModel model, JProgressBar pBar, Console con) {
        this.model = model;
        this.pBar = pBar;
        this.con = con;
    }

    @Override
    public void run() {
        con.clear();
        pBar.setVisible(true);
        pBar.setString("CA operations");
        pBar.setStringPainted(true);
        // Get caDirectories and base data
        con.add("Certificate maintenance operations", HEAD);
        con.add("Issuing CA certificates fom root...", EVENT);
        pBar.setValue(10);
        // Root CA actions
        issueCAcerts();
        con.add("Creating CRLs...", EVENT);
        pBar.setValue(30);
        // Revocation
        revokeCerts();
        pBar.setValue(60);
        // Publish data
        con.add("Publishing data...", EVENT);
        publishCaData();
        pBar.setVisible(false);
        pBar.setStringPainted(false);

        con.add("CA maintenance completed", EVENT);
        setChanged();
        notifyObservers(COMPLETE);
    }

    private void revokeCerts() {
        for (CertificationAuthority ca : model.getCaList()) {
            int cnt = ca.revokeCertificates();
            con.add("Revoked", String.valueOf(cnt) + " certs from " + ca.getCaName(), ACTION);
        }
    }

    private void publishCaData() {
        for (CertificationAuthority ca : model.getCaList()) {
            File exportCrlFile = ca.getExportCrlFile();
            File crlFile = ca.getCrlFile();
            if (crlFile.canRead()) {
                FileOps.createDir(exportCrlFile.getParentFile().getAbsolutePath());
                FileOps.saveByteFile(FileOps.readBinaryFile(crlFile), exportCrlFile);
                con.add("Exported", exportCrlFile.getAbsolutePath(), ACTION);
            }
        }
    }

    private void issueCAcerts() {
        RootCertificationAuthority rootCa = model.getRootCa();
        for (CertificationAuthority ca : model.getCaList()) {
            //Ignore the root
            if (!ca.equals(rootCa)) {
                CertPath certPath = ca.getCertPath();
                if (certPath == null) {
                    X509Certificate xCert = rootCa.issueXCert(ca.getSelfSignedCert());
                    certPath = new CertPath();
                    try {
                        certPath.add(PEM.getPemCert(xCert.getEncoded()));
                        certPath.add(PEM.getPemCert(rootCa.getSelfSignedCert().getEncoded()));
                        ca.setCertPath(certPath);
                        con.add("CA cert issued for", ca.getCaName(), ACTION);
                    } catch (CertificateEncodingException ex) {
                        Logger.getLogger(CaDaemonOperations.class.getName()).log(Level.SEVERE, null, ex);
                    }

                }
            }
        }
    }
}
