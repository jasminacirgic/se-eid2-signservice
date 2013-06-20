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
package com.aaasec.sigserv.cssigapp.db;

/**
 * Trust store database.
 */
import com.aaasec.sigserv.cssigapp.data.DbTrustStore;
import java.math.BigInteger;
import java.util.logging.Level;
import java.sql.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

public class TrustStoreTable extends SqliteUtil<DbTrustStore> {

    public static final String DATA_TABLE = "TrustStore";
    private static final String KEY_COL = "PkHash";
    private static final String TABLE_CONSTRUCT =
            "PkHash VARCHAR(255) not NULL,"
            + "Cert VARCHAR(65535),"
            + "Source VARCHAR(255),";

    public TrustStoreTable(String dbFileName) {
        super(dbFileName, TABLE_CONSTRUCT, DATA_TABLE, KEY_COL);
    }

    @Override
    PreparedStatement dataStoragePreparedStatement(Connection con, DbTrustStore ts, boolean replace) {
        String action = (replace) ? "INSERT OR REPLACE" : "INSERT";
        PreparedStatement prep = null;

        try {
            prep = con.prepareStatement(
                    action + " INTO " + table + " VALUES (?,?,?);");
            prep.setString(1, ts.getPkHash());
            prep.setString(2, ts.getPemCert());
            prep.setString(3, ts.getSource());
        } catch (SQLException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }

        return prep;
    }

    @Override
    void processDatabaseRecordValues(ResultSet rs, List<DbTrustStore> valueList) {
        try {
            while (rs.next()) {
                DbTrustStore ks = new DbTrustStore();
                ks.setPkHash(rs.getString(1));
                ks.setPemCert(rs.getString(2));
                ks.setSource(rs.getString(3));
                valueList.add(ks);
            }
            rs.close();
        } catch (SQLException ex) {
            Logger.getLogger(TrustStoreTable.class.getName()).log(Level.WARNING, null, ex);
        }
    }

    @Override
    String getKeyColumnStringValue(DbTrustStore tr) {
        return String.valueOf(tr.getPkHash());
    }

    public Map<BigInteger, DbTrustStore> getTrustStoreMap() {
        List<DbTrustStore> allRecords = getAllRecords();
        return getTrustStoreMap(allRecords);
    }

    public Map<BigInteger, DbTrustStore> getTrustStoreMap(String column, String value) {
        List<DbTrustStore> records = getRecords(column, value);
        return getTrustStoreMap(records);
    }

    public Map<BigInteger, DbTrustStore> getTrustStoreMap(List<DbTrustStore> records) {
        Map<BigInteger, DbTrustStore> paramMap = new HashMap<BigInteger, DbTrustStore>();
        for (DbTrustStore ts : records) {
            paramMap.put(new BigInteger(ts.getPkHash()), ts);
        }
        return paramMap;
    }
}
