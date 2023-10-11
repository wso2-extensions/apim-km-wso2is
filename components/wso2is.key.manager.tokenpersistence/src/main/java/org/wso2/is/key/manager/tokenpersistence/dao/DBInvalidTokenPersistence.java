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

package org.wso2.is.key.manager.tokenpersistence.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.is.key.manager.tokenpersistence.model.InvalidTokenPersistenceService;
import org.wso2.is.key.manager.tokenpersistence.utils.DBUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.UUID;

/**
 * RDBMS based invalid token persistence implementation
 */
public class DBInvalidTokenPersistence implements InvalidTokenPersistenceService {
    private static final Log log = LogFactory.getLog(DBInvalidTokenPersistence.class);
    private static DBInvalidTokenPersistence instance = null;

    public static final String IS_INVALID_TOKEN =
            "SELECT 1 FROM AM_INVALID_TOKENS WHERE SIGNATURE = ? AND CONSUMER_KEY = ? ";
    
    public static final String INSERT_INVALID_TOKEN = 
            "INSERT INTO AM_INVALID_TOKENS (UUID, SIGNATURE, CONSUMER_KEY, EXPIRY_TIMESTAMP) "
            + "VALUES (?,?,?,?)";
    public static final String DELETE_INVALID_TOKEN = "DELETE FROM AM_INVALID_TOKENS WHERE EXPIRY_TIMESTAMP < ?";

    public static final String IS_INTERNALLY_REVOKED_CONSUMER_KEY = "SELECT 1 FROM AM_INTERNAL_TOKEN_REVOCATION WHERE "
            + "CONSUMER_KEY = ? AND TIME_REVOKED > ?";
    
    public static final String INSERT_CONSUMER_KEY_EVENT_RULE = "INSERT " +
            "INTO IDN_INTERNAL_TOKEN_REVOCATION_CONSUMER_KEY_EVENTS\n" +
            "(CONSUMER_KEY, IS_REVOKE_APP_ONLY, TIME_REVOKED, TENANT_ID)\n" +
            "VALUES (?, ?, ?, ?) AS COLS\n" +
            "ON DUPLICATE KEY UPDATE\n" +
            "TIME_REVOKED = COLS.TIME_REVOKED";
    public static final String INSERT_USER_EVENT_RULE = "INSERT " +
            "INTO IDN_INTERNAL_TOKEN_REVOCATION_USER_EVENTS\n" +
            "(USER_ID, TIME_REVOKED)\n" +
            "VALUES (?, ?) AS COLS\n" +
            "ON DUPLICATE KEY UPDATE\n" +
            "TIME_REVOKED = COLS.TIME_REVOKED";
    private DBInvalidTokenPersistence() {

    }
    public static synchronized DBInvalidTokenPersistence getInstance() {

        if (instance == null) {
            instance = new DBInvalidTokenPersistence();
        }
        return instance;
    }

    @Override
    public boolean isInvalidToken(String token, String consumerKey) throws IdentityOAuth2Exception {

        log.debug("Validate invalid token from the database.");
        try (Connection connection = DBUtil.getConnection()) {
            try (PreparedStatement preparedStatement = connection.prepareStatement(IS_INVALID_TOKEN)) {
                preparedStatement.setString(1, token);
                preparedStatement.setString(2, consumerKey);
                try (ResultSet resultSet = preparedStatement.executeQuery()) {
                    return resultSet.next();
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while checking existence of token as an invalid token.", e);
        }
    }

    @Override
    public void addInvalidToken(String token, String consumerKey, Long expiryTime)
            throws IdentityOAuth2Exception {

        log.debug("Insert invalid toke to the database");
        try (Connection connection = DBUtil.getConnection()) {
            try (PreparedStatement preparedStatement = connection.prepareStatement(INSERT_INVALID_TOKEN)) {
                connection.setAutoCommit(false);
                preparedStatement.setString(1, UUID.randomUUID().toString());
                preparedStatement.setString(2, token);
                preparedStatement.setString(3, consumerKey);
                preparedStatement.setLong(4, expiryTime);
                preparedStatement.executeUpdate();
                connection.commit();
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while checking existence of token as an invalid token.", e);
        }
        removeExpiredJWTs();
    }

    public void removeExpiredJWTs() throws IdentityOAuth2Exception {

        try (Connection connection = DBUtil.getConnection(); PreparedStatement ps =
                connection.prepareStatement(DELETE_INVALID_TOKEN)) {
            connection.setAutoCommit(false);
            ps.setLong(1, System.currentTimeMillis());
            ps.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while deleting expired invalid token entries", e);
        }
    }

    /**
     * Check whether any internally revoked JWT rule is present for the given consumer key which is revoked after the
     * given timestamp.
     *
     * @param consumerKey Consumer key of the application.
     * @param timeStamp   Timestamp to check the revoked JWT.
     * @throws IdentityOAuth2Exception If an error occurs while checking the existence of the revoked JWT.
     */
    public boolean isRevokedJWTConsumerKeyExist(String consumerKey, Date timeStamp) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Check whether internally revoked JWT rule is present for the consumer key: " + consumerKey);
        }
        try (Connection connection = DBUtil.getConnection();
             PreparedStatement ps = connection.prepareStatement(IS_INTERNALLY_REVOKED_CONSUMER_KEY)) {
            ps.setString(1, consumerKey);
            ps.setTimestamp(2, new java.sql.Timestamp(timeStamp.getTime()));
            try (ResultSet resultSet = ps.executeQuery()) {
                return resultSet.next();
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while checking existence of internally revoked JWT for consumer "
                    + "key: " + consumerKey, e);
        }
    }

    @Override
    public void revokeAccessTokensByUserEvent(String userID, long revocationTime)
            throws IdentityOAuth2Exception {

        try (Connection connection = DBUtil.getConnection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement preparedStatement = connection.prepareStatement(INSERT_USER_EVENT_RULE)) {
                preparedStatement.setString(1, userID);
                preparedStatement.setTimestamp(2, new Timestamp(revocationTime));
                int rowsAffected = preparedStatement.executeUpdate();
                if (log.isDebugEnabled()) {
                    if (rowsAffected == 1) {
                        log.debug("User event token revocation rule inserted successfully.");
                    }
                    if (rowsAffected == 2) {
                        log.debug("User event token revocation rule updated successfully.");
                    }
                }
                connection.commit();
            } catch (SQLException e) {
                connection.rollback();
                throw new IdentityOAuth2Exception("Error while inserting user event revocation rule to db.", e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while inserting user event revocation rule to db.", e);
        }
    }

    @Override
    public void revokeAccessTokensByConsumerKeyEvent(String consumerKey, boolean isRevokeAppOnly,
                                                     long revocationTime, int tenantId) throws IdentityOAuth2Exception {

        try (Connection connection = DBUtil.getConnection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement preparedStatement = connection.prepareStatement(INSERT_CONSUMER_KEY_EVENT_RULE)) {
                preparedStatement.setString(1, consumerKey);
                preparedStatement.setBoolean(2, isRevokeAppOnly);
                preparedStatement.setTimestamp(3, new Timestamp(revocationTime));
                preparedStatement.setInt(4, tenantId);
                int rowsAffected = preparedStatement.executeUpdate();
                if (log.isDebugEnabled()) {
                    if (rowsAffected == 1) {
                        log.debug("Consumer key event token revocation rule inserted successfully.");
                    }
                    if (rowsAffected == 2) {
                        log.debug("Consumer key event token revocation rule updated successfully.");
                    }
                }
                connection.commit();
            } catch (SQLException e) {
                connection.rollback();
                throw new IdentityOAuth2Exception("Error while inserting consumer key event revocation rule to db.", e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while inserting consumer key event revocation rule to db.", e);
        }
    }
}
