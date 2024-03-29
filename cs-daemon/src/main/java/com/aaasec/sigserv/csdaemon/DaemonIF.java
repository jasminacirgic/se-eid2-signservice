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
package com.aaasec.sigserv.csdaemon;

import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.ObservableFrameCloser;
import com.aaasec.sigserv.cscommon.ObserverConstants;
import com.aaasec.sigserv.csdaemon.ca.CaDaemonOperations;
import com.aaasec.sigserv.csdaemon.ca.utils.HtmlTable;
import com.aaasec.sigserv.csdaemon.html.HtmlElement;
import com.aaasec.sigserv.cssigapp.ca.CaKeyStoreConstants;
import com.aaasec.sigserv.cssigapp.ca.CertPath;
import com.aaasec.sigserv.cssigapp.ca.CertificationAuthority;
import com.aaasec.sigserv.cssigapp.data.DbCALog;
import com.aaasec.sigserv.cssigapp.data.DbCert;
import com.aaasec.sigserv.cssigapp.utils.ASN1Util;
import com.aaasec.sigserv.cssigapp.utils.CertificateUtils;
import com.aaasec.sigserv.cssigapp.utils.KsCertFactory;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Observable;
import java.util.Observer;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JEditorPane;
import javax.swing.JLabel;

/**
 * This class provides an internal frame with the information caching UI
 */
public final class DaemonIF extends javax.swing.JInternalFrame implements Observer, ObserverConstants, Constants, CaKeyStoreConstants {

    private static final Logger LOG = Logger.getLogger(DaemonIF.class.getName());
    private static final Object CA_TIMER = "TrustTimer";
    private long caTime = 720000;
    private Thread caThread;
    private CaDaemonOperations caDeamon;
    private ResourceBundle uiText = ResourceBundle.getBundle("adUiText");
    private ObservableFrameCloser frameCloser;
    private boolean stop;
    private DaemonModel model;
    private CertificationAuthority currentCa;
    private X509Certificate currentCaCert = null;
    private X509CRL currentCrl = null;
    private Console con;
    boolean frameInitComplete = false;
    private List<List<Object>> certIndexMap = new ArrayList<List<Object>>();
    private List<List<Object>> logIndexMap = new ArrayList<List<Object>>();
    private BigInteger currentSelectedSerial;

    /**
     * Creates new form DaemonIF 
     */
    public DaemonIF(DaemonModel model, Observer closeObserver) {
        super("Central Signing Service Daemon",
                true, //resizable
                false, //closable
                true, //maximizable
                true);//iconifiable
        initComponents();
        this.setVisible(true);

        jProgressBar.setVisible(false);

        this.model = model;
        caTime = (long) model.getSigModel().getConf().getCrlValidityHours() * 60 * 60 * 500;
        frameCloser = new ObservableFrameCloser(this, closeObserver);
        con = new Console(jTextPaneConsole, 2);
        caDeamon = new CaDaemonOperations(model, jProgressBar, con);
        addObservers();
        refreshCombobox();

        jEditorPaneCertificates.setContentType("text/html");
        jEditorPaneLog.setContentType("text/html");
        jEditorPaneCertificates.setText("");
        jEditorPaneLog.setText("");
        jCheckBoxReverse.setSelected(true);
        frameInitComplete = true;
        updateCertTables();
        caOperations();
    }

    private void addObservers() {
        caDeamon.addObserver(this);
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup1 = new javax.swing.ButtonGroup();
        jPanel1 = new javax.swing.JPanel();
        jSplitPane1 = new javax.swing.JSplitPane();
        jPanel3 = new javax.swing.JPanel();
        jComboBoxCaSelect = new javax.swing.JComboBox();
        jCheckBoxReverse = new javax.swing.JCheckBox();
        jPanel4 = new javax.swing.JPanel();
        jTabbedPaneTables = new javax.swing.JTabbedPane();
        jScrollPane1 = new javax.swing.JScrollPane();
        jEditorPaneCertificates = new javax.swing.JEditorPane();
        jScrollPane3 = new javax.swing.JScrollPane();
        jEditorPaneLog = new javax.swing.JEditorPane();
        jButtonRevoke = new javax.swing.JButton();
        jPanel2 = new javax.swing.JPanel();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTextPaneConsole = new javax.swing.JTextPane();
        jPanel5 = new javax.swing.JPanel();
        jProgressBar = new javax.swing.JProgressBar();
        jLabelTimer = new javax.swing.JLabel();
        jButtonConsole = new javax.swing.JButton();
        jButtonRoot = new javax.swing.JButton();
        jButtonCRL = new javax.swing.JButton();

        jSplitPane1.setDividerLocation(700);

        jComboBoxCaSelect.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "Item 1", "Item 2", "Item 3", "Item 4" }));
        jComboBoxCaSelect.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBoxCaSelectActionPerformed(evt);
            }
        });

        jCheckBoxReverse.setText("Recent on top");
        jCheckBoxReverse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxReverseActionPerformed(evt);
            }
        });

        jEditorPaneCertificates.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                jEditorPaneCertificatesMouseReleased(evt);
            }
        });
        jScrollPane1.setViewportView(jEditorPaneCertificates);

        jTabbedPaneTables.addTab("Certificates", jScrollPane1);

        jEditorPaneLog.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                jEditorPaneLogMouseReleased(evt);
            }
        });
        jScrollPane3.setViewportView(jEditorPaneLog);

        jTabbedPaneTables.addTab("Log", jScrollPane3);

        org.jdesktop.layout.GroupLayout jPanel4Layout = new org.jdesktop.layout.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 698, Short.MAX_VALUE)
            .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(org.jdesktop.layout.GroupLayout.TRAILING, jTabbedPaneTables))
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 743, Short.MAX_VALUE)
            .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(jTabbedPaneTables, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 743, Short.MAX_VALUE))
        );

        jButtonRevoke.setText("Toggle Revoked Status");
        jButtonRevoke.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonRevokeActionPerformed(evt);
            }
        });

        org.jdesktop.layout.GroupLayout jPanel3Layout = new org.jdesktop.layout.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel3Layout.createSequentialGroup()
                .add(jComboBoxCaSelect, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .add(18, 18, 18)
                .add(jButtonRevoke)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, 262, Short.MAX_VALUE)
                .add(jCheckBoxReverse)
                .addContainerGap())
            .add(jPanel4, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel3Layout.createSequentialGroup()
                .add(jPanel3Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jComboBoxCaSelect, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jCheckBoxReverse)
                    .add(jButtonRevoke))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(jPanel4, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jSplitPane1.setLeftComponent(jPanel3);

        jScrollPane2.setViewportView(jTextPaneConsole);

        jLabelTimer.setText("Next 00:00:00");

        jButtonConsole.setText("Console");
        jButtonConsole.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonConsoleActionPerformed(evt);
            }
        });

        jButtonRoot.setText("CA Cert");
        jButtonRoot.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonRootActionPerformed(evt);
            }
        });

        jButtonCRL.setText("CRL");
        jButtonCRL.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonCRLActionPerformed(evt);
            }
        });

        org.jdesktop.layout.GroupLayout jPanel5Layout = new org.jdesktop.layout.GroupLayout(jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout.setHorizontalGroup(
            jPanel5Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(org.jdesktop.layout.GroupLayout.TRAILING, jPanel5Layout.createSequentialGroup()
                .add(jButtonConsole, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 77, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                .add(jButtonRoot, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 85, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                .add(jButtonCRL)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, 143, Short.MAX_VALUE)
                .add(jProgressBar, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(jLabelTimer))
        );
        jPanel5Layout.setVerticalGroup(
            jPanel5Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel5Layout.createSequentialGroup()
                .add(jPanel5Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(jLabelTimer)
                    .add(jProgressBar, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jPanel5Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                        .add(jButtonConsole)
                        .add(jButtonRoot)
                        .add(jButtonCRL)))
                .addContainerGap(11, Short.MAX_VALUE))
        );

        org.jdesktop.layout.GroupLayout jPanel2Layout = new org.jdesktop.layout.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel5, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .add(jScrollPane2, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 626, Short.MAX_VALUE)
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel2Layout.createSequentialGroup()
                .add(jPanel5, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 40, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(jScrollPane2, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 713, Short.MAX_VALUE)
                .addContainerGap())
        );

        jSplitPane1.setRightComponent(jPanel2);

        org.jdesktop.layout.GroupLayout jPanel1Layout = new org.jdesktop.layout.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(org.jdesktop.layout.GroupLayout.TRAILING, jSplitPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 1337, Short.MAX_VALUE)
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(org.jdesktop.layout.GroupLayout.TRAILING, jSplitPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 785, Short.MAX_VALUE)
        );

        org.jdesktop.layout.GroupLayout layout = new org.jdesktop.layout.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(layout.createSequentialGroup()
                .addContainerGap()
                .add(jPanel1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(org.jdesktop.layout.GroupLayout.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .add(jPanel1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jComboBoxCaSelectActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBoxCaSelectActionPerformed
        if (frameInitComplete) {
            updateCertTables();
        }
    }//GEN-LAST:event_jComboBoxCaSelectActionPerformed

    private void jCheckBoxReverseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxReverseActionPerformed
        if (frameInitComplete) {
            updateCertTables();
        }
    }//GEN-LAST:event_jCheckBoxReverseActionPerformed

    private void jButtonConsoleActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonConsoleActionPerformed
        jTextPaneConsole.setText("");
        con.renderText();
    }//GEN-LAST:event_jButtonConsoleActionPerformed

    private void jButtonRootActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonRootActionPerformed
        displayCurrentCAcert();
    }//GEN-LAST:event_jButtonRootActionPerformed

    private void jButtonCRLActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonCRLActionPerformed
        if (currentCrl != null) {
            jTextPaneConsole.setText(currentCrl.toString(true));
        }
    }//GEN-LAST:event_jButtonCRLActionPerformed

    private void jEditorPaneLogMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jEditorPaneLogMouseReleased
        BigInteger certSerial = getSelectedSerial(jEditorPaneLog, logIndexMap, jEditorPaneLog.getCaretPosition());
        displaySelectedCert(certSerial);
    }//GEN-LAST:event_jEditorPaneLogMouseReleased

    private void jEditorPaneCertificatesMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jEditorPaneCertificatesMouseReleased
        BigInteger certSerial = getSelectedSerial(jEditorPaneCertificates, certIndexMap, jEditorPaneCertificates.getCaretPosition());
        displaySelectedCert(certSerial);
    }//GEN-LAST:event_jEditorPaneCertificatesMouseReleased

    private void jButtonRevokeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonRevokeActionPerformed
        revokeSelectedCert();
    }//GEN-LAST:event_jButtonRevokeActionPerformed
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JButton jButtonCRL;
    private javax.swing.JButton jButtonConsole;
    private javax.swing.JButton jButtonRevoke;
    private javax.swing.JButton jButtonRoot;
    private javax.swing.JCheckBox jCheckBoxReverse;
    private javax.swing.JComboBox jComboBoxCaSelect;
    private javax.swing.JEditorPane jEditorPaneCertificates;
    private javax.swing.JEditorPane jEditorPaneLog;
    private javax.swing.JLabel jLabelTimer;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JProgressBar jProgressBar;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JTabbedPane jTabbedPaneTables;
    private javax.swing.JTextPane jTextPaneConsole;
    // End of variables declaration//GEN-END:variables

    private void caOperations() {
        if (running(caThread)) {
            try {
                caThread.join();
            } catch (InterruptedException ex) {
                LOG.log(Level.WARNING, ex.getLocalizedMessage());
            }
        }
        model.reloadCAs();
        caThread = new Thread(caDeamon);
        caThread.setDaemon(true);
        caThread.start();
        startCacheTimer();
    }

    private boolean running(Thread thread) {
        return (thread != null && thread.isAlive());
    }

    public void stopDeamon() {
        stop = true;
        if (running(caThread)) {
            return;
        }
        killCacheIf();
    }

    private void startCacheTimer() {
        long cycle = caTime;
        CacheTimer timer = new CacheTimer(cycle, CA_TIMER);
        timer.addObserver(this);
        Thread timerThread = new Thread(timer);
        timerThread.isDaemon();
        timerThread.start();
    }

    private void updateTimerLabel(JLabel label, long millisec) {
        StringBuilder b = new StringBuilder();
        int hours = (int) millisec / (1000 * 60 * 60);
        int days = hours / 24;
        hours %= 24;
        int min = (int) (millisec / (1000 * 60)) % 60;
        int sec = (int) (millisec / 1000) % 60;

        b.append("Next: ");
        if (days > 0) {
            b.append(String.valueOf(days)).append("d ");
        }
        b.append((hours < 10) ? "0" : "").append(String.valueOf(hours)).append(":");
        b.append((min < 10) ? "0" : "").append(String.valueOf(min)).append(":");
        b.append((sec < 10) ? "0" : "").append(String.valueOf(sec));

        label.setText(b.toString());
    }

    /**
     * Return method for the Observable class
     * @param o The class being observed
     * @param arg The return argument from the observed class
     */
    public void update(Observable o, Object arg) {
        if (o instanceof CacheTimer) {
            if (arg.equals(CA_TIMER)) {
                caOperations();
            }
        }
        if (o instanceof CaDaemonOperations) {
            if (arg.equals(COMPLETE)) {
                if (stop) {
                    caThread = null;
                    killCacheIf();
                } else {
                    refreshCombobox();
                    updateCertTables();
                }
            }
        }
    }

    /**
     * getter for the stop caching state.
     * @return true if this cache daemon has been requested to be stopped by the user.
     */
    public boolean isStop() {
        return stop;
    }

    private void killCacheIf() {
        frameCloser.close(CACHEDEAMON_CLOSE);
    }

    private void refreshCombobox() {
        int selected = jComboBoxCaSelect.getSelectedIndex();
        jComboBoxCaSelect.removeAllItems();

        for (CertificationAuthority ca : model.getCaList()) {
            jComboBoxCaSelect.addItem(ca);
        }

        int items = jComboBoxCaSelect.getItemCount();
        if (items > 0 && items >= selected) {
            jComboBoxCaSelect.setSelectedIndex(selected);
        }
    }

    private void updateCertTables() {
        try {
            //Get root
            currentCa = (CertificationAuthority) jComboBoxCaSelect.getSelectedItem();
            currentCaCert = null;
            if (currentCa != null && currentCa.isInitialized()) {
                currentCaCert = currentCa.getSelfSignedCert();
                //Get current CRL
                if (currentCa.getExportCrlFile().canRead()) {
                    currentCrl = KsCertFactory.getCRL(FileOps.readBinaryFile(currentCa.getExportCrlFile()));
                }

                getDbCertTable(currentCa.getAllCertificates());
                getLogTable(currentCa.getCertLogs());
            }
        } catch (Exception ex) {
            LOG.warning("Certificate table display halted on Exception: " + ex.getMessage());
        }


    }

    private void getDbCertTable(List<DbCert> dbcerts) {
        // Set Charge table data
        certIndexMap.clear();
        int lastIndex = 0;
        String[] tableHead = new String[]{
            "Issue Time",
            "Serial#",
            "Subject",
            "Revoked",
            "Revoke Date"};

        int len = stringArrayLen(tableHead);
        List<Object> titleIndex = setRowIndex(0, len, BigInteger.ZERO);
        certIndexMap.add(titleIndex);
        lastIndex = len;

        HtmlTable certTable = new HtmlTable();
        HtmlTable.RowStyle rowStyle = HtmlTable.RowStyle.HEADING;
        certTable.addRow(tableHead, HtmlTable.Type.CERTHEADING, rowStyle);

        int row = 0;

        if (jCheckBoxReverse.isSelected()) {
            Collections.reverse(dbcerts);
        }

        for (DbCert crt : dbcerts) {
            Calendar revokeTime = Calendar.getInstance();
            revokeTime.setTimeInMillis(crt.getRevDate());
            String revDateStr = "";
            if (crt.getRevDate() > 0) {
                revDateStr = TIME_FORMAT.format(revokeTime.getTime());
            }
            String revStr = "valid";
            if (crt.getRevoked() == 1) {
                revStr = "revoked";
            }
            String[] tableRowData = new String[]{
                String.valueOf(TIME_FORMAT.format(crt.getIssueDate())),
                shortStr(crt.getSerialStr(), 10),
                ASN1Util.getShortCertName(crt.getCertificate()),
                revStr,
                revDateStr};

            rowStyle = (row++ % 2 == 0) ? HtmlTable.RowStyle.EVEN : HtmlTable.RowStyle.ODD;
            certTable.addRow(tableRowData, HtmlTable.Type.CERT, rowStyle);

            // Add indexValues
            len = stringArrayLen(tableRowData);
            List<Object> rowIndex = setRowIndex(lastIndex, lastIndex + len, crt.getSerial());
            lastIndex += len;
            certIndexMap.add(rowIndex);
        }
        jEditorPaneCertificates.setText(getHtmlContent(certTable));
        jEditorPaneCertificates.setCaretPosition(0);
    }

    private String shortStr(String inpStr, int len){
        String str = (inpStr.length()>len)?inpStr.substring(0, len)+"..." :inpStr;
        return str;
    }
    
    private void getLogTable(List<DbCALog> certLogs) {
        // Set Charge table data
        logIndexMap.clear();
        int lastIndex = 0;
        String[] tableHead = new String[]{
            "Log time",
            "Event",
            "Serial#",
            "Reasons"};

        int len = stringArrayLen(tableHead);
        List<Object> titleIndex = setRowIndex(0, len, BigInteger.ZERO);
        logIndexMap.add(titleIndex);
        lastIndex = len;

        HtmlTable logTable = new HtmlTable();
        HtmlTable.RowStyle rowStyle = HtmlTable.RowStyle.HEADING;
        logTable.addRow(tableHead, HtmlTable.Type.LOGHEADING, rowStyle);

        GregorianCalendar gc = new GregorianCalendar();
        if (jCheckBoxReverse.isSelected()) {
            Collections.reverse(certLogs);
        }
        int row = 0;
        for (DbCALog log : certLogs) {
            gc.setTimeInMillis(log.getLogTime());
            String logTime = (TIME_FORMAT.format(gc.getTime()));
            String event = (log.getEventString());
            DbCALog.Parameters param = model.getSigModel().getGson().fromJson(log.getLogParameter(), DbCALog.Parameters.class);
            BigInteger certSerial = param.serial;
            String reason = "";
            if (log.getLogCode() == REVOKE_EVENT) {
                long rc = param.reason;
                reason = ((rc < 11) ? REV_REASON[(int) rc] : String.valueOf(rc));
            }
            String[] tableRowData = new String[]{
                logTime,
                event,
                String.valueOf(certSerial),
                reason
            };
            rowStyle = (row++ % 2 == 0) ? HtmlTable.RowStyle.EVEN : HtmlTable.RowStyle.ODD;
            logTable.addRow(tableRowData, HtmlTable.Type.LOG, rowStyle);

            // Add indexValues
            len = stringArrayLen(tableRowData);
            List<Object> rowIndex = setRowIndex(lastIndex, lastIndex + len, certSerial);
            lastIndex += len;
            logIndexMap.add(rowIndex);
        }
        jEditorPaneLog.setText(getHtmlContent(logTable));
        jEditorPaneLog.setCaretPosition(0);
    }

    private int stringArrayLen(String[] stringArray) {
        int len = 0;
        for (String str : stringArray) {
            len += str.length() + 1;
        }
        return len;
    }

    private List<Object> setRowIndex(int start, int end, BigInteger serial) {
        List<Object> intList = new ArrayList<Object>(3);

        intList.add(start);
        intList.add(end);
        intList.add(serial);

        return intList;
    }

    private void selectRow(JEditorPane editorPane, List<Object> indexList) {
        try {
            int start = (Integer) indexList.get(0);
            int end = (Integer) indexList.get(1);
            editorPane.setSelectionStart(start);
            editorPane.setSelectionEnd(end);
        } catch (Exception ex) {
        }
    }

    private BigInteger getSelectedSerial(JEditorPane editorPane, List<List<Object>> valueList, int caretPosition) {

        List<Object> indexList = null;
        BigInteger serial = null;

        for (List<Object> values : valueList) {
            indexList = values;
            int start = (Integer) indexList.get(0);
            int end = (Integer) indexList.get(1);
            serial = (BigInteger) indexList.get(2);
            if (caretPosition >= start && caretPosition < end) {
                break;
            }
        }

        selectRow(editorPane, indexList);
        return serial;
    }

    private String getHtmlContent(HtmlElement element) {
        StringBuilder b = new StringBuilder();
        b.append("<html><body>");
        b.append(element.toString());
        b.append("</body></html>");
        return b.toString();
    }

    private void displaySelectedCert(BigInteger serial) {
        if (serial == null || currentCa == null) {
            return;
        }
        DbCert cert = currentCa.getCertificateBySerial(serial);
        jTextPaneConsole.setText(null);
        if (cert != null) {
            jTextPaneConsole.setText(cert.getCertificate().toString(true));
            jTextPaneConsole.setCaretPosition(0);
            currentSelectedSerial = serial;
        }
    }

    private long longValue(Object valueAt) {
        long value = 0;
        try {
            value = Long.valueOf((String) valueAt);
        } catch (Exception ex) {
        }
        try {
            value = Long.valueOf((Long) valueAt);
        } catch (Exception ex) {
        }
        return value;
    }

    private void revokeSelectedCert() {
        if (currentSelectedSerial == null|| jTabbedPaneTables.getSelectedIndex()!=0) {
            return;
        }
        DbCert dBCert = currentCa.getCertificateBySerial(currentSelectedSerial);
        if (dBCert.getRevoked() == 0) {
            currentCa.revokeCertificate(currentSelectedSerial);
        } else {
            try {
                boolean onCrl = currentCrl.isRevoked(currentSelectedSerial);
                if (!onCrl) {
                    dBCert.setRevoked(0);
                    dBCert.setRevDate(0);
                    currentCa.getCertDb().addOrReplaceRecord(dBCert);
                }
            } catch (Exception ex) {
            }
        }
        updateCertTables();
    }

    private void displayCurrentCAcert() {
        if (currentCa == null) {
            return;
        }
        CertPath certPath = currentCa.getCertPath();
        if (certPath == null && currentCaCert == null) {
            return;
        }
        if (certPath == null) {
            jTextPaneConsole.setText(currentCaCert.toString(true));
            return;
        }
        X509Certificate certificate = CertificateUtils.getCertificate(certPath.get(0));
        if (certificate==null){
            jTextPaneConsole.setText(currentCaCert.toString(true));
            return;            
        }
            jTextPaneConsole.setText(certificate.toString(true));
    }

    class CacheTimer extends Observable implements Runnable {

        long waitTime;
        Object closeMessage;
        JLabel displayLabel;

        public CacheTimer(long time, Object closeMessage) {
            this.waitTime = time;
            this.closeMessage = closeMessage;
            this.displayLabel = jLabelTimer;
        }

        public void run() {
            long stopTime = System.currentTimeMillis() + waitTime;
            while (System.currentTimeMillis() < stopTime) {
                updateTimerLabel(displayLabel, (stopTime - System.currentTimeMillis()));
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ex) {
                    LOG.log(Level.WARNING, ex.getLocalizedMessage());
                }
            }
            setChanged();
            notifyObservers(closeMessage);
        }
    }
}
