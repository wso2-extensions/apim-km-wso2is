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

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.is.key.manager.tokenpersistence.model.InvalidTokenPersistenceService;
import org.wso2.is.key.manager.tokenpersistence.utils.PersistenceDatabaseUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.util.UUID;

/**
 * RDBMS based invalid token persistence implementation.
 */
public class DBInvalidTokenPersistence implements InvalidTokenPersistenceService {
    private static final Log log = LogFactory.getLog(DBInvalidTokenPersistence.class);
    private static final DBInvalidTokenPersistence instance = new DBInvalidTokenPersistence();

    private DBInvalidTokenPersistence() {

    }

    public static synchronized DBInvalidTokenPersistence getInstance() {

        return instance;
    }

    @Override
    public boolean isInvalidToken(String token, String consumerKey) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug(String.format("Validating the token: %s from the database.",
                        DigestUtils.sha256Hex(token)));
            } else {
                log.debug("Validating the token from the database.");
            }
        }
        try (Connection connection = PersistenceDatabaseUtil.getConnection()) {
            try (PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.IS_INVALID_TOKEN)) {
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

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug(String.format("Insert invalid token (hashed): %s for consumer key: %s with expiry time: %s",
                        DigestUtils.sha256Hex(token), consumerKey, expiryTime));
            } else {
                log.debug(String.format("Insert invalid token for consumer key: %s with expiry time: %s",
                        DigestUtils.sha256Hex(token), consumerKey, expiryTime));
            }
        }
        try (Connection connection = PersistenceDatabaseUtil.getConnection()) {
            try (PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.INSERT_INVALID_TOKEN)) {
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

        try (Connection connection = PersistenceDatabaseUtil.getConnection(); PreparedStatement ps =
                connection.prepareStatement(SQLQueries.DELETE_INVALID_TOKEN)) {
            connection.setAutoCommit(false);
            ps.setLong(1, System.currentTimeMillis());
            ps.executeUpdate();
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while deleting expired invalid token entries", e);
        }
    }

    @Override
    public boolean isTokenRevokedForConsumerKey(String consumerKey, Date tokenIssuedTime)
            throws IdentityOAuth2Exception {

        /*
         * Check whether any internally revoked event is persisted for the given consumer key which is revoked after
         * the given token issued timestamp.
         */
        if (log.isDebugEnabled()) {
            log.debug(String.format("Check whether any internally revoked event is present for the consumer key: %s "
                    + "after issuing the token at: %s", consumerKey, tokenIssuedTime));
        }
        try (Connection connection = PersistenceDatabaseUtil.getConnection();
             PreparedStatement ps = connection.prepareStatement(SQLQueries.IS_APP_REVOKED_EVENT)) {
            ps.setString(1, consumerKey);
            ps.setTimestamp(2, new java.sql.Timestamp(tokenIssuedTime.getTime()));
            try (ResultSet resultSet = ps.executeQuery()) {
                return resultSet.next();
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while checking existence of internally revoked JWT for consumer "
                    + "key: " + consumerKey, e);
        }
    }

    @Override
    public boolean isTokenRevokedForSubjectEntity(String entityId, Date tokenIssuedTime)
            throws IdentityOAuth2Exception {

        /*
         * Check whether any internally revoked event is persisted for the given entity which is revoked after
         * the given token issued timestamp.
         */
        if (log.isDebugEnabled()) {
            log.debug(String.format("Check whether any internally revoked event is present for the subject entity "
                    + "id: %s after issuing the token at: %s", entityId, tokenIssuedTime));
        }
        try (Connection connection = PersistenceDatabaseUtil.getConnection();
             PreparedStatement ps = connection.prepareStatement(SQLQueries.IS_SUBJECT_ENTITY_REVOKED_EVENT)) {
            ps.setString(1, entityId);
            ps.setTimestamp(2, new java.sql.Timestamp(tokenIssuedTime.getTime()));
            try (ResultSet resultSet = ps.executeQuery()) {
                return resultSet.next();
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while checking existence of internally revoked JWT for subject "
                    + "entity id: " + entityId, e);
        }
    }

    @Override
    public void revokeTokensByUserEvent(String subjectId, String subjectIdType,
                                        long revocationTime, String organization) throws IdentityOAuth2Exception {

        try (Connection connection = PersistenceDatabaseUtil.getConnection()) {
            connection.setAutoCommit(false);
            String updateQuery = SQLQueries.UPDATE_SUBJECT_ENTITY_REVOKED_EVENT;
            try (PreparedStatement ps = connection.prepareStatement(updateQuery)) {
                ps.setTimestamp(1, new Timestamp(revocationTime),
                        Calendar.getInstance(TimeZone.getTimeZone("UTC")));
                ps.setString(2, subjectId);
                ps.setString(3, subjectIdType);
                ps.setString(4, organization);
                int rowsAffected = ps.executeUpdate();

                if (rowsAffected == 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("User event token revocation rule not found. Inserting new rule.");
                    }
                    connection.rollback();
                    String insertQuery = SQLQueries.INSERT_SUBJECT_ENTITY_REVOKED_EVENT;
                    try (PreparedStatement ps1 = connection.prepareStatement(insertQuery)) {
                        ps1.setString(1, subjectId);
                        ps1.setString(2, subjectIdType);
                        ps1.setTimestamp(3, new Timestamp(revocationTime),
                                Calendar.getInstance(TimeZone.getTimeZone("UTC")));
                        ps1.setString(4, organization);
                        ps1.execute();
                        connection.commit();
                    } catch (SQLIntegrityConstraintViolationException e) {
                        log.warn("User event token revocation rule already persisted");
                        connection.rollback();
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("User event token revocation rule updated.");
                    }
                    connection.commit();
                }
            } catch (SQLException e) {
                connection.rollback();
                throw new IdentityOAuth2Exception("Error while inserting user event revocation rule to db."
                        + e.getMessage(), e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while inserting user event revocation rule to db."
                    + e.getMessage(), e);
        }
    }

    @Override
    public void revokeTokensByConsumerKeyEvent(String consumerKey, long revocationTime, String organization)
            throws IdentityOAuth2Exception {

        try (Connection connection = PersistenceDatabaseUtil.getConnection()) {
            connection.setAutoCommit(false);
            String updateQuery = SQLQueries.UPDATE_APP_REVOKED_EVENT;
            try (PreparedStatement ps = connection.prepareStatement(updateQuery)) {
                ps.setTimestamp(1, new Timestamp(revocationTime),
                        Calendar.getInstance(TimeZone.getTimeZone("UTC")));
                ps.setString(2, consumerKey);
                ps.setString(3, organization);

                int rowsAffected = ps.executeUpdate();

                if (rowsAffected == 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("Consumer key event token revocation rule not found. Inserting new rule.");
                    }
                    connection.rollback();
                    String insertQuery = SQLQueries.INSERT_SUBJECT_ENTITY_REVOKED_EVENT;
                    try (PreparedStatement ps1 = connection.prepareStatement(insertQuery)) {
                        ps1.setString(1, consumerKey);
                        ps1.setTimestamp(2, new Timestamp(revocationTime),
                                Calendar.getInstance(TimeZone.getTimeZone("UTC")));
                        ps1.setString(3, organization);
                        ps1.execute();
                    } catch (SQLIntegrityConstraintViolationException e) {
                        log.warn("Consumer key event token revocation rule already persisted");
                        connection.rollback();
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Consumer key event token revocation rule updated.");
                    }
                    connection.commit();
                }
            } catch (SQLException e) {
                connection.rollback();
                throw new IdentityOAuth2Exception("Error while inserting consumer key event revocation rule to db."
                        + e.getMessage(), e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while inserting consumer key event revocation rule to db."
                    + e.getMessage(), e);
        }
    }
}
