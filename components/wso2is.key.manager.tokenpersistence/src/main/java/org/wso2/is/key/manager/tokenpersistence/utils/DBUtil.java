/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com)
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.is.key.manager.tokenpersistence.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityRuntimeException;

import java.sql.Connection;
import java.sql.SQLException;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

/**
 * Utility class for database operations.
 */
public class DBUtil {

    private static final Log log = LogFactory.getLog(DBUtil.class);
    private static volatile DataSource dataSource = null;
    private static final String DEFAULT_DATASTORE = "jdbc/WSO2_PERSISTENCE_DB";

    public static void initialize() throws IdentityRuntimeException {

        if (dataSource != null) {
            return;
        }
        synchronized (DBUtil.class) {
            if (dataSource == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Initializing data source");
                }

                String dataSourceName = System.getProperty("revoked.token.datasource");
                if (dataSourceName == null) {
                    dataSourceName = DEFAULT_DATASTORE;
                }

                try {
                    Context ctx = new InitialContext();
                    dataSource = (DataSource) ctx.lookup(dataSourceName);
                } catch (NamingException e) {
                    throw new IdentityRuntimeException("Error while looking up the data " + "source: " + dataSourceName,
                            e);
                }
            }
        }
    }

    /**
     * Utility method to get a new database connection.
     *
     * @return Connection
     * @throws SQLException if failed to get Connection
     */
    public static Connection getConnection() throws SQLException {

        if (dataSource == null) {
            initialize();
        }
        return dataSource.getConnection();
    }
}
