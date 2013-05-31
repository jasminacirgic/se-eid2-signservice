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

import com.aaasec.sigserv.cscommon.SqLiteConnectionPool;
import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.sql.*;
import java.util.LinkedList;
import java.util.List;

/**
 * Abstract class handling basic database operations for a database table. This
 * table is used to retrieve and store objects of types specified by the E class.
 * @author stefan Santesson, 3xA Security
 * @param <E> The class of database data objects. The database table 
 * handled by this class stores and retrieves data to and from database objects of this class.
 */
public abstract class SqliteUtil<E extends Object> {

    protected static final Logger LOG = Logger.getLogger(SqliteUtil.class.getName());
    protected String userid = "iaik", password = "iaik";
    protected String url, dbFileName;
    protected String tableStruct, table, keyColumn;

    /**
     * Constructor initiating the database table if needed
     * @param dbFileName The name of the database file including its full absolute path
     * @param tableStructure String holding the create table instructions
     * @param tableName The name of the database table handled by this database object
     * @param keyColumn The name of the primary key column of the table
     */
    public SqliteUtil(String dbFileName, String tableStructure, String tableName, String keyColumn) {
        this.dbFileName = dbFileName;
        this.tableStruct =
                "CREATE TABLE IF NOT EXISTS " + tableName + " ("
                + tableStructure
                + "PRIMARY KEY ( " + keyColumn + " ) )";
        this.table = tableName;
        this.keyColumn = keyColumn;
        init();
    }

    protected final void init() {
        url = "jdbc:sqlite://" + dbFileName;
        File dbFile = new File(dbFileName);
        if (!dbFile.canRead()) {
            if (dbFile.getParentFile() != null) {
                dbFile.getParentFile().mkdirs();
            }
        }
        createDbTable();
    }

    /**
     * Create Db table according to the array of tableStruct strings
     */
    protected void createDbTable() {
        Statement stmt;
        try {
            Connection con = SqLiteConnectionPool.getConnection(url, userid, password);
            stmt = con.createStatement();
            stmt.executeUpdate(tableStruct);
            stmt.close();
            con.close();

        } catch (SQLException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }
//        LOG.info("DB: " + url + " :" + table + " table initialized");
    }

    /**
     * Adds or replaces a database record
     * @param record The java object holding record data
     */
    public void addOrReplaceRecord(E record) {
        addOrReplaceRecord(record, true);
    }

    /**
     * Adds or replaces a database record
     * @param record The java object holding record data
     * @param replace true = replace record if it already exists, false = do not replace any existing record
     */
    public void addOrReplaceRecord(E record, boolean replace) {
        
        final E rec = record;
        final boolean repl = replace;
        
        SqLiteAction dbAction = new SqLiteAction(url, userid, password) {

            @Override
            PreparedStatement getPrepStatement(Connection con) throws SQLException {
                return dataStoragePreparedStatement(con, rec, repl);
            }
        };        
        dbAction.execute();                
    }

    /**
     * Get all database records from the target database table
     * @return a list of all database records
     */
    public List<E> getAllRecords() {
        return getRecords(keyColumn, null);
    }

    /**
     * Get a specific database record
     * @param value the value of the key column of the target record
     * @return the target database record, null of no such record exists
     */
    public E getDbRecord(String value) {
        List<E> records = getRecords(keyColumn, value);
        if (records.size() > 0) {
            return (E) records.get(0);
        }
        return null;
    }

    /**
     * Get specified records matching the query criteria
     * @param column The column where to look for matching values 
     * @param value the value to match in String form
     * @return Data object obtained from the database query
     */
    public List<E> getRecords(String column, String value) {
        String qString = "";
        if (value == null) {
            qString = "SELECT * FROM " + table + " ORDER BY " + column + " ASC ;";
        } else {
            qString = "SELECT * FROM " + table + " WHERE " + column + " = \"" + value + "\" order by " + keyColumn + ";";
        }

        SqLiteQuery<List<E>> dbQuery = new SqLiteQuery<List<E>>(url, userid, password) {

            @Override
            List<E> parseResultSet(ResultSet rs) throws SQLException {
                List<E> valueList = new LinkedList<E>();
                processDatabaseRecordValues(rs, valueList);
                return valueList;
            }
        };
        
        List<E> result = dbQuery.execute(qString, new LinkedList<E>());
        
        return result;
    }

    /**
     * Delete database record
     * @param record the record to delete
     * @return the number of records deleted as a result of this function call
     */
    public int deteleDbRecord(E record) {
        return deleteRecord(keyColumn, getKeyColumnStringValue(record));
    }

    /**
     * Delete database record mating the query criteria
     * @param column The column used to search match values
     * @param value The column value of the record(s) to delete
     * @return the number of deleted records
     */
    public int deleteRecord(String column, String value) {
        Statement stmt;
        int cnt = 0;

        try {
            Connection con = SqLiteConnectionPool.getConnection(url, userid, password);
            stmt = con.createStatement();
            cnt = stmt.executeUpdate("DELETE FROM " + table + " WHERE " + column + " = \"" + value + "\" ;");
            con.close();

        } catch (Exception ex) {
            LOG.log(Level.SEVERE, null, ex);
        }
        return cnt;
    }

    /**
     * Returns a sqLite PreparedStatement for storing data into the database
     * @param con the database connection
     * @param record the record to store or update in the database  
     * @param replace true if the presented record should replace an old record if exist, 
     * false of no existing records should be replaced
     * @return a PreparedStatement
     */
    abstract PreparedStatement dataStoragePreparedStatement(Connection con, E record, boolean replace);

    /**
     * Process the values obtained from the database
     * @param rs The result set obtained from the database
     * @param valueList A list of data objects obtained from the database
     */
    abstract void processDatabaseRecordValues(ResultSet rs, List<E> valueList);

    /**
     * Get a string representation of the value of the key column from a specific record object
     * @param record the target record object
     * @return a string representation of the object key value
     */
    abstract String getKeyColumnStringValue(E record);
}
