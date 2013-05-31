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

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import oasisNamesTcSAMLMetadataUi.UIInfoDocument;
import oasisNamesTcSAMLMetadataUi.UIInfoType;
import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import x0Metadata.oasisNamesTcSAML2.EntitiesDescriptorDocument;
import x0Metadata.oasisNamesTcSAML2.ExtensionsType;

/**
 * Class for parsing SAML Metadata.
 */
public final class MetaData {

    private Document doc;
    private List<String> entityIds;
    private Map<String, Map> nameMap;
    private Map<String, String> certMap;
    private Map<String, String> typeMap;
    private File xmlFile;
    private boolean initialized = false;
    private static final String LF = System.getProperty("line.separator");
    private Thread recacheThread;
    private RefreshCache refreshCache;
    private long lastRecache = 0;
    private int refreshMinutes;
    private long cacheInterval;
    private final static Logger LOG = Logger.getLogger(MetaData.class.getName());
    private EntitiesDescriptorDocument metadataDoc;

    public MetaData(File xmlFile, int refreshMinutes) {
        this.xmlFile = xmlFile;
        this.refreshMinutes = refreshMinutes;
        if (xmlFile.canRead()) {
            LOG.info("Can read metadata cache - " + xmlFile.getAbsolutePath());
        } else {
            LOG.warning("no metadata cache - " + xmlFile.getAbsolutePath());
        }
        cacheInterval = refreshMinutes * 1000 * 60;
        lastRecache = System.currentTimeMillis();
        start();
    }

    public void start() {
        try {
            InputStream is = new FileInputStream(xmlFile);

            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            doc = dBuilder.parse(is);
            doc.getDocumentElement().normalize();
            parseXML2();
            lastRecache = System.currentTimeMillis();

        } catch (Exception ex) {
            Logger.getLogger(MetaData.class.getName()).log(Level.WARNING, null, ex);
        }
    }
//        try {
//            metadataDoc = EntitiesDescriptorDocument.Factory.parse(xmlFile);
//            parseXML2();
//            lastRecache = System.currentTimeMillis();
//        } catch (XmlException ex) {
//            LOG.warning(ex.getMessage());
//        } catch (IOException ex) {
//            LOG.warning(ex.getMessage());
//        }
//
//    }

//    private void parseXML() {
//        try {
//            entityIds = new ArrayList<String>();
//            nameMap = new HashMap<String, Map>();
//            certMap = new HashMap<String, String>();
//            typeMap = new HashMap<String, String>();
//
//            Map<String, String> idpDisplName;
//
//            EntitiesDescriptorType entitiesDescriptor = metadataDoc.getEntitiesDescriptor();
//            EntityDescriptorType[] edArray = entitiesDescriptor.getEntityDescriptorArray();
//
//            for (EntityDescriptorType ed : edArray) {
//                String entityID = ed.getEntityID();
//                addEntityId(entityID);
//                //If Entity is an SP
//                SPSSODescriptorType[] spssoDescriptorArray = ed.getSPSSODescriptorArray();
//                if (spssoDescriptorArray.length > 0) {
//                    typeMap.put(entityID, "SPSSODescriptor");
//                    SPSSODescriptorType sp = spssoDescriptorArray[0];
//                    KeyDescriptorType[] keyDescriptorArray = sp.getKeyDescriptorArray();
//                    addSigningKeys(keyDescriptorArray, certMap, entityID);
//                }
//
//
//                // If entity is an IdP
//                IDPSSODescriptorType[] idpssoArray = ed.getIDPSSODescriptorArray();
//                if (idpssoArray.length > 0) {
//                    typeMap.put(entityID, "IDPSSODescriptor");
//                    IDPSSODescriptorType idp = idpssoArray[0];
//                    KeyDescriptorType[] keyDescriptorArray = idp.getKeyDescriptorArray();
//                    addSigningKeys(keyDescriptorArray, certMap, entityID);
//                }
//
//            }
//
//            LOG.info("Metadata Initialized: Names (" + nameMap.size() + ") Certs(" + certMap.size() + ") types(" + typeMap.size() + ")");
//            initialized = true;
//            LOG.info("https://eid2cssp.3xasecurity.com/sign --> " + getName("https://eid2cssp.3xasecurity.com/sign", "en"));
//        } catch (NullPointerException ex) {
//            ex.printStackTrace();
//            initialized = false;
//        }
//    }
//
//    private void addSigningKeys(KeyDescriptorType[] kdArray, Map<String, String> certMap, String entityId) {
//        for (KeyDescriptorType kd : kdArray) {
//            Enum use = kd.getUse();
//            if (use == null || use.equals(KeyTypes.SIGNING)) {
//                try {
//                    byte[] certBytes = kd.getKeyInfo().getX509DataArray(0).getX509CertificateArray(0);
//                    if (certBytes.length > 0) {
//                        String cert = String.valueOf(Base64Coder.encode(certBytes));
//                        certMap.put(entityId, cert);
//                    }
//                } catch (Exception ex) {
//                }
//            }
//        }
//    }
    private void parseXML2() {
        try {
            entityIds = new ArrayList<String>();
            nameMap = new HashMap<String, Map>();
            certMap = new HashMap<String, String>();
            typeMap = new HashMap<String, String>();
            HashMap<String, String> idpDisplName;


            NodeList entityNodes = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "EntityDescriptor");
            for (int i = 0; i < entityNodes.getLength(); i++) {
                Node entityNode = entityNodes.item(i);
                NodeList entityElements = entityNode.getChildNodes();

                if (entityElements.item(1).getNodeName().indexOf("IDPSSODescriptor") != -1) {
                    String entityID = entityNode.getAttributes().getNamedItem("entityID").getTextContent();
                    entityIds.add(entityID);
                    idpDisplName = new HashMap<String, String>();
                    nameMap.put(entityID, idpDisplName);
                }
            }

            String[] types = {"IDPSSODescriptor", "SPSSODescriptor", "md:IDPSSODescriptor", "md:SPSSODescriptor"};
            for (String type : types) {
                NodeList typeNodes = doc.getElementsByTagName(type);
                for (int i = 0; i < typeNodes.getLength(); i++) {
                    Node orgNode = typeNodes.item(i);
                    String parentEntityId = getParentEntityId(orgNode);
                    if (parentEntityId == null) {
                        continue;
                    }
                    addEntityId(parentEntityId);
                    if (!typeMap.containsKey(parentEntityId)) {
                        typeMap.put(parentEntityId, type);
                    }
                }
            }

            types = new String[]{"X509Certificate", "ds:X509Certificate"};
            for (String type : types) {

                NodeList certNodes = doc.getElementsByTagName(type);
                for (int i = 0; i < certNodes.getLength(); i++) {
                    Node certNode = certNodes.item(i);
                    String parentEntityId = getParentEntityId(certNode);
                    if (parentEntityId == null) {
                        continue;
                    }
                    boolean signCert = isSignCert(certNode);
                    if (!signCert) {
                        continue;
                    }
                    String cert = certNode.getTextContent();
                    if (cert != null && cert.length() > 0) {
                        certMap.put(parentEntityId, cert);
                    }
                }
            }

            types = new String[]{"OrganizationDisplayName", "md:OrganizationDisplayName"};
            for (String type : types) {
                NodeList orgNodes = doc.getElementsByTagName(type);
                for (int i = 0; i < orgNodes.getLength(); i++) {
                    Node orgNode = orgNodes.item(i);
                    String parentEntityId = getParentEntityId(orgNode);
                    if (parentEntityId == null) {
                        continue;
                    }
                    addEntityId(parentEntityId);
                    addToNameMap(orgNode, parentEntityId);

                }
            }
            LOG.info("Metadata Initialized: Names (" + nameMap.size() + ") Certs(" + certMap.size() + ") types(" + typeMap.size() + ")");
            initialized = true;
            LOG.info("https://eid2cssp.3xasecurity.com/sign --> " + getName("https://eid2cssp.3xasecurity.com/sign", "en"));
        } catch (NullPointerException ex) {
            initialized = false;
        }
    }

    static UIInfoType getUIInfoList(ExtensionsType ext) {
        if (ext == null) {
            return null;
        }
        Node domNode = ext.getDomNode();
        NodeList childNodes = domNode.getChildNodes();
        int length = childNodes.getLength();
        for (int i = 0; i < length; i++) {
            Node node = childNodes.item(i);
            String nodeName = node.getLocalName();
            if (nodeName != null) {
                if (nodeName.equals("UIInfo")) {
                    try {
                        UIInfoDocument mduiDoc = UIInfoDocument.Factory.parse(node);
                        return mduiDoc.getUIInfo();
                    } catch (XmlException ex) {
                    }
                }
            }
        }
        return null;
    }

    private String getParentEntityId(Node node) {
        Node p = node.getParentNode();

        try {
            while (p != null && p.getNodeName().indexOf("EntityDescriptor") == -1) {
                p = p.getParentNode();
            }
            if (p != null) {
                String entityID = p.getAttributes().getNamedItem("entityID").getTextContent();
                return entityID;
            }
        } catch (Exception ex) {
        }
        return null;
    }

    private boolean isSignCert(Node certNode) {
        boolean signCert = false;
        Node p = certNode.getParentNode();

        try {
            while (p != null && p.getNodeName().indexOf("KeyDescriptor") == -1) {
                p = p.getParentNode();
            }
            if (p != null) {
                Node useAttr = p.getAttributes().getNamedItem("use");
                signCert = true;
                // If a use attribute is present and it states someting other than signing, reject
                if (useAttr != null) {
                    String useAttrValue = useAttr.getTextContent();
                    if (!useAttrValue.equalsIgnoreCase("signing")) {
                        signCert = false;
                    }
                }
            }
        } catch (Exception ex) {
        }
        return signCert;
    }

    private void addToNameMap(Node orgNode, String entityID) {
        String lang = orgNode.getAttributes().getNamedItem("xml:lang").getTextContent();
        String orgDisp = orgNode.getTextContent();
        //Store Idp Name
        Map<String, String> idpDisplName = nameMap.get(entityID);
        idpDisplName.put(lang, orgDisp);
    }

    private void addEntityId(String entityId) {
        if (!entityIds.contains(entityId)) {
            entityIds.add(entityId);
            Map<String, String> idpDisplName = new HashMap<String, String>();
            nameMap.put(entityId, idpDisplName);
        }
    }

//    private List<String> getOrderedLangList(Map<String, String> dispNames) {
//        List<String> langList = new ArrayList<String>();
//        Set<String> keySet = dispNames.keySet();
//        //Look for english first
//        for (String lang : keySet) {
//            if (lang.equalsIgnoreCase("en")) {
//                langList.add(lang);
//            }
//        }
//        //Add rest
//        for (String lang : keySet) {
//            if (!lang.equalsIgnoreCase("en")) {
//                langList.add(lang);
//            }
//        }
//        return langList;
//
//    }
    private void reCache() {
        if (System.currentTimeMillis() < (lastRecache + cacheInterval)) {
            return;
        }
        if (running(recacheThread)) {
            return;
        }
        recacheThread = new Thread(refreshCache);
        recacheThread.setDaemon(true);
        recacheThread.start();
    }

    private boolean running(Thread thread) {
        return (thread != null && thread.isAlive());
    }

    public List<String> getEntityIds() {
        reCache();
        return entityIds;
    }

    public boolean isInitialized() {
        reCache();
        return initialized;
    }

    public Map<String, String> getCertMap() {
        reCache();
        return certMap;
    }

    public Map<String, Map> getNameMap() {
        reCache();
        return nameMap;
    }

    public String getName(String entityId, String prefLang) {
        reCache();
        String name = entityId;
        try {
            Map langMap = nameMap.get(entityId);
            if (langMap.containsKey(prefLang)) {
                return (String) langMap.get(prefLang);
            }
            if (langMap.containsKey("en")) {
                return (String) langMap.get("en");
            }
        } catch (Exception ex) {
        }
        return name;
    }

    public Map<String, String> getTypeMap() {
        reCache();
        return typeMap;
    }

    class RefreshCache implements Runnable {

        public void run() {
            MetaData md = new MetaData(xmlFile, refreshMinutes);
            if (md.isInitialized()) {
                entityIds = md.getEntityIds();
                nameMap = md.getNameMap();
                certMap = md.getCertMap();
                typeMap = md.getTypeMap();
                lastRecache = System.currentTimeMillis();
            }

        }
    }
}
