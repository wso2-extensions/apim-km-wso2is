/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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
package org.wso2.is.key.manager.tokenpersistence.dao;

import org.apache.commons.logging.*;
import org.wso2.carbon.identity.oauth2.*;
import org.wso2.is.key.manager.tokenpersistence.utils.*;

import java.sql.*;
import java.util.*;

public class DBInternalRevocationEventService implements InternalRevocationEventService {

    private static final Log log = LogFactory.getLog(DBInternalRevocationEventService.class);
    private static DBInternalRevocationEventService instance = null;

    public static final String IS_VALID_TOKEN =
            "SELECT 1 FROM AM_INTERNAL_TOKEN_REVOCATION WHERE clientId = ? AND authorizedUser = ? AND tenantId = ? ";

    public static final String INSERT_AM_INTERNAL_TOKEN_REVOCATION =
            "INSERT INTO AM_INTERNAL_TOKEN_REVOCATION (id, clientId, user_uuid, tenantId, timestamp) "
                    + "VALUES (?,?,?,?,?,?)";

    public static synchronized DBInternalRevocationEventService getInstance() {
        if (instance == null) {
            instance = new DBInternalRevocationEventService();
        }
        return instance;
    }

    private DBInternalRevocationEventService() {
    }


    /**
     * Add an event to the revocate a token internally.
     *
     * @param clientId       Client ID
     * @param authorizedUser user
     * @param tenantId       tenantId
     * @return
     */
    @Override
    public boolean addEvent(String clientId, String authorizedUser, String tenantId) throws IdentityOAuth2Exception {
        log.debug("Insert internal token invalidation event to the database");
        try (Connection connection = DBUtil.getConnection()) {
            try (PreparedStatement preparedStatement = connection.prepareStatement(INSERT_AM_INTERNAL_TOKEN_REVOCATION)) {
                connection.setAutoCommit(false);
                preparedStatement.setString(1, UUID.randomUUID().toString());
                preparedStatement.setString(2, clientId);
                preparedStatement.setString(3, authorizedUser);
                preparedStatement.setString(4, tenantId);
                Timestamp timestamp = new Timestamp(System.currentTimeMillis());
                preparedStatement.setString(5, String.valueOf(timestamp.getTime()));
                preparedStatement.executeUpdate();
                connection.commit();
                return true;
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while adding token invalidation event.", e);
        }
    }

    /**
     * Check whether a specific token is revoked or not
     */
    @Override
    public boolean isTokenValid(String clientId, String authorizedUser, String tenantId) throws
            IdentityOAuth2Exception {
        log.debug("Validating whether the token is an internally revocated token or not" );
        try (Connection connection = DBUtil.getConnection()) {
            try (PreparedStatement preparedStatement = connection.prepareStatement(IS_VALID_TOKEN)) {
                preparedStatement.setString(1, clientId);
                preparedStatement.setString(2, authorizedUser);
                preparedStatement.setString(3, tenantId);
                try (ResultSet resultSet = preparedStatement.executeQuery()) {
                    return resultSet.next();
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while checking existence of token as an invalid token.", e);
        }
    }

    /**
     * clean events when a user gets deleted.
     *
     * @param username  username
     * @param timestamp timestamp of the user deletion.
     * @param tenantId  tenantId of the user deletion.
     * @return
     */
    @Override
    public boolean cleanEventsByUser(String username, String timestamp, String tenantId) throws
            IdentityOAuth2Exception {
        return false;
    }


    /**
     * Clean events by tenant.
     *
     * @param tenantId tenant Id
     * @return
     */
    @Override
    public boolean cleanEventsByTenant(String tenantId) throws IdentityOAuth2Exception {
        return false;
    }
}
