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

import com.aaasec.sigserv.cscommon.config.ConfigData;
import com.aaasec.sigserv.cscommon.enums.Enums;
import iaik.asn1.ObjectID;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Configuration data with default values for attribute mapping configuration.
 */
public class AttrMapConfig implements ConfigData {

    private Map<String, MapAttributes> attrMap = new HashMap<String, MapAttributes>();

    @Override
    public String getName() {
        return "attrMap";
    }

    @Override
    public void setDefaults() {

        // Serial Number
        attrMap.put("rdn:" + ObjectID.serialNumber.getID(), new MapAttributes(new String[]{
                    Enums.idAttributes.get("personalIdentityNumber"),
                    Enums.idAttributes.get("mail")
                }, new int[]{0, 1}, "serialNumber", null, true));

        // Common Name
        attrMap.put("rdn:" + ObjectID.commonName.getID(), new MapAttributes(new String[]{
                    Enums.idAttributes.get("displayName"),
                    Enums.idAttributes.get("cn")
                }, new int[]{0, 1}, "commonName", null, false));

        // Given Name
        attrMap.put("rdn:" + ObjectID.givenName.getID(), new MapAttributes(
                Enums.idAttributes.get("givenName"), "givenName", true));

        // Surname
        attrMap.put("rdn:" + ObjectID.surName.getID(), new MapAttributes(
                Enums.idAttributes.get("sn"), "surname", true));

        // country
        attrMap.put("rdn:" + ObjectID.country.getID(), new MapAttributes(new String[]{
                    Enums.idAttributes.get("country")
                }, null, "country", "SE", true));

        // e-mail
        attrMap.put("san:1", new MapAttributes(
                Enums.idAttributes.get("mail"), "e-mail", false));
    }

    public AttrMapConfig() {
    }

    public Map<String, MapAttributes> getAttrMap() {
        return attrMap;
    }

    public void setAttrMap(Map<String, MapAttributes> attrMap) {
        this.attrMap = attrMap;
    }

    public class MapAttributes {

        public boolean required = false;
        public String friendlyName;
        public String defaultValue;
        public List<SAMLAttrName> samlAttributeNames = new ArrayList<SAMLAttrName>();

        public MapAttributes(String samlAttrName, String name, boolean required) {
            this(new String[]{samlAttrName}, null, name, null, required);
        }

        public MapAttributes(String[] samlAttrArray, int[] orderArray, String name, String defaultVal, boolean required) {
            this.required = required;
            this.friendlyName = name;

            for (int i = 0; i < samlAttrArray.length; i++) {
                int order = 0;
                if (orderArray != null && orderArray.length > i) {
                    order = orderArray[i];
                }
                samlAttributeNames.add(new SAMLAttrName("urn:oid:" + samlAttrArray[i], order));
            }
            this.defaultValue = defaultVal;
        }

        public class SAMLAttrName {

            public String name;
            public int order;

            public SAMLAttrName() {
            }

            public SAMLAttrName(String name, int order) {
                this.name = name;
                if (order > -1) {
                    this.order = order;
                }
            }
        }
    }
}
