/*
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com)
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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.is.key.manager.tokenpersistence.PersistenceConstants;
import org.wso2.is.key.manager.tokenpersistence.model.InvalidTokenPersistenceService;

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

import static org.wso2.carbon.identity.core.util.IdentityUtil.getProperty;

/**
 * RDBMS based invalid token persistence implementation.
 */
public class DBInvalidTokenPersistence implements InvalidTokenPersistenceService {
    private static final Log log = LogFactory.getLog(DBInvalidTokenPersistence.class);
    private static final DBInvalidTokenPersistence instance = new DBInvalidTokenPersistence();
    private static final String OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT = "OAuth.TokenPersistence.RetryCount";
    private static final int DEFAULT_TOKEN_PERSIST_RETRY_COUNT = 5;

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
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
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
                log.debug(String.format("Insert invalid token for consumer key: %s with expiry time: %s", consumerKey,
                        expiryTime));
            }
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.INSERT_INVALID_TOKEN)) {
                preparedStatement.setString(1, UUID.randomUUID().toString());
                preparedStatement.setString(2, token);
                preparedStatement.setString(3, consumerKey);
                preparedStatement.setTimestamp(4, new Timestamp(expiryTime),
                        Calendar.getInstance(TimeZone.getTimeZone(PersistenceConstants.UTC)));
                preparedStatement.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception(String.format("Failed to add invalid token for consumer key: %s with "
                        + "expiry time: %s", consumerKey, expiryTime), e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception(String.format("Failed to add invalid token for consumer key: %s with "
                    + "expiry time: %s", consumerKey, expiryTime), e);
        }
        removeExpiredJWTs();
    }

    public void removeExpiredJWTs() throws IdentityOAuth2Exception {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps =
                         connection.prepareStatement(SQLQueries.DELETE_INVALID_TOKEN)) {
                ps.setTimestamp(1, new Timestamp(System.currentTimeMillis()), Calendar.getInstance(
                        TimeZone.getTimeZone(PersistenceConstants.UTC)));
                ps.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception("Error while deleting expired invalid token entries", e);
            }
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
            log.debug(String.format("Checking whether any internally revoked event is present for the consumer key: %s "
                    + "after issuing the token at: %s", consumerKey, tokenIssuedTime));
        }
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = connection.prepareStatement(SQLQueries.IS_APP_REVOKED_EVENT)) {
            ps.setString(1, consumerKey);
            ps.setTimestamp(2, new Timestamp(tokenIssuedTime.getTime()),
                    Calendar.getInstance(TimeZone.getTimeZone(PersistenceConstants.UTC)));
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
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps = connection.prepareStatement(SQLQueries.IS_SUBJECT_ENTITY_REVOKED_EVENT)) {
            ps.setString(1, entityId);
            ps.setTimestamp(2, new Timestamp(tokenIssuedTime.getTime()),
                    Calendar.getInstance(TimeZone.getTimeZone(PersistenceConstants.UTC)));
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
                                        long revocationTime, String organization, int retryAttemptCounter)
            throws IdentityOAuth2Exception {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            String updateQuery = SQLQueries.UPDATE_SUBJECT_ENTITY_REVOKED_EVENT;
            try (PreparedStatement ps = connection.prepareStatement(updateQuery)) {
                ps.setTimestamp(1, new Timestamp(revocationTime),
                        Calendar.getInstance(TimeZone.getTimeZone(PersistenceConstants.UTC)));
                ps.setString(2, subjectId);
                ps.setString(3, subjectIdType);
                ps.setString(4, organization);
                int rowsAffected = ps.executeUpdate();
                if (rowsAffected == 0) {
                    log.debug("User event token revocation rule not found. Inserting new rule.");
                    IdentityDatabaseUtil.rollbackTransaction(connection);
                    String insertQuery = SQLQueries.INSERT_SUBJECT_ENTITY_REVOKED_EVENT;
                    try (PreparedStatement ps1 = connection.prepareStatement(insertQuery)) {
                        ps1.setString(1, UUID.randomUUID().toString());
                        ps1.setString(2, subjectId);
                        ps1.setString(3, subjectIdType);
                        ps1.setTimestamp(4, new Timestamp(revocationTime),
                                Calendar.getInstance(TimeZone.getTimeZone(PersistenceConstants.UTC)));
                        ps1.setString(5, organization);
                        ps1.execute();
                        IdentityDatabaseUtil.commitTransaction(connection);
                        if (retryAttemptCounter > 0) {
                            log.info("Successfully recovered CON_SUB_EVT_KEY constraint violation with the attempt : "
                                    + retryAttemptCounter);
                        }
                    } catch (SQLIntegrityConstraintViolationException e) {
                        rollbackUserEventTransaction(connection);
                        retryOnConstraintViolationException(retryAttemptCounter, subjectId, subjectIdType,
                                revocationTime, organization, e);
                    } catch (SQLException e) {
                        rollbackUserEventTransaction(connection);
                        // Handle constrain violation issue in JDBC drivers which does not throw
                        // SQLIntegrityConstraintViolationException
                        if (StringUtils.containsIgnoreCase(e.getMessage(), "CON_SUB_EVT_KEY")) {
                            retryOnConstraintViolationException(retryAttemptCounter, subjectId, subjectIdType,
                                    revocationTime, organization, e);
                        } else {
                            throw new IdentityOAuth2Exception("Error while inserting user event revocation rule to db."
                                    + e.getMessage(), e);
                        }
                    } catch (Exception e) {
                        rollbackUserEventTransaction(connection);
                        // Handle constrain violation issue in JDBC drivers which does not throw
                        // SQLIntegrityConstraintViolationException or SQLException.
                        if (StringUtils.containsIgnoreCase(e.getMessage(), "CON_SUB_EVT_KEY") || (e.getCause() != null
                                && StringUtils.containsIgnoreCase(e.getCause().getMessage(), "CON_SUB_EVT_KEY"))
                                || (e.getCause() != null && e.getCause().getCause() != null &&
                                StringUtils.containsIgnoreCase(e.getCause().getCause().getMessage(),
                                        "CON_SUB_EVT_KEY"))) {
                            retryOnConstraintViolationException(retryAttemptCounter, subjectId, subjectIdType,
                                    revocationTime, organization, e);
                        } else {
                            throw new IdentityOAuth2Exception("Error while inserting user event revocation rule to db."
                                    + e.getMessage(), e);
                        }
                    }
                } else {
                    log.debug("User event token revocation rule updated.");
                    IdentityDatabaseUtil.commitTransaction(connection);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception("Error while inserting user event revocation rule to db."
                        + e.getMessage(), e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while inserting user event revocation rule to db."
                    + e.getMessage(), e);
        }
    }

    /**
     * Retry the user event token revocation event persisting transaction on constraint violation exception.
     *
     * @param retryAttemptCounter Retry attempt counter
     * @param subjectId           Subject id
     * @param subjectIdType       Subject id type
     * @param revocationTime      Revocation time
     * @param organization        Organization
     * @param exception           Constraint Violation Exception
     * @throws IdentityOAuth2Exception If maximum retry count exceeds
     */
    private void retryOnConstraintViolationException(int retryAttemptCounter, String subjectId, String subjectIdType,
                                                     long revocationTime, String organization, Exception exception)
            throws IdentityOAuth2Exception {

        String errorMessage = String.format("User event token revocation rule for subject id : %s, "
                        + "type : %s and organization : %s already exists", subjectId,
                subjectIdType, organization);
        if (retryAttemptCounter >= getTokenPersistRetryCount()) {
            log.error("CON_SUB_EVT_KEY constraint violation retry count exceeds the maximum");
            throw new IdentityOAuth2Exception(errorMessage, exception);
        }
        revokeTokensByUserEvent(subjectId, subjectIdType, revocationTime, organization,
                retryAttemptCounter + 1);
    }

    /**
     * Rollback the user event token revocation event persisting transaction.
     *
     * @param connection Connection
     */
    private void rollbackUserEventTransaction(Connection connection) {

        log.warn("User event token revocation rule already persisted.");
        IdentityDatabaseUtil.rollbackTransaction(connection);
    }

    @Override
    public void revokeTokensByConsumerKeyEvent(String consumerKey, long revocationTime, String organization,
                                               int retryAttemptCounter)
            throws IdentityOAuth2Exception {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            String updateQuery = SQLQueries.UPDATE_APP_REVOKED_EVENT;
            try (PreparedStatement ps = connection.prepareStatement(updateQuery)) {
                ps.setTimestamp(1, new Timestamp(revocationTime),
                        Calendar.getInstance(TimeZone.getTimeZone(PersistenceConstants.UTC)));
                ps.setString(2, consumerKey);
                ps.setString(3, organization);
                int rowsAffected = ps.executeUpdate();
                if (rowsAffected == 0) {
                    log.debug("Consumer key event token revocation rule not found. Inserting new rule.");
                    IdentityDatabaseUtil.rollbackTransaction(connection);
                    String insertQuery = SQLQueries.INSERT_APP_REVOKED_EVENT;
                    try (PreparedStatement ps1 = connection.prepareStatement(insertQuery)) {
                        ps1.setString(1, UUID.randomUUID().toString());
                        ps1.setString(2, consumerKey);
                        ps1.setTimestamp(3, new Timestamp(revocationTime),
                                Calendar.getInstance(TimeZone.getTimeZone(PersistenceConstants.UTC)));
                        ps1.setString(4, organization);
                        ps1.execute();
                        IdentityDatabaseUtil.commitTransaction(connection);
                        if (retryAttemptCounter > 0) {
                            log.info("Successfully recovered CON_APP_EVT_KEY constraint violation with the attempt : "
                                    + retryAttemptCounter);
                        }
                    } catch (SQLIntegrityConstraintViolationException e) {
                        rollbackConsumerAppEventTransaction(connection);
                        retryOnConstraintViolationException(consumerKey, revocationTime, organization,
                                retryAttemptCounter, e);
                    } catch (SQLException e) {
                        rollbackConsumerAppEventTransaction(connection);
                        // Handle constrain violation issue in JDBC drivers which does not throw
                        // SQLIntegrityConstraintViolationException
                        if (StringUtils.containsIgnoreCase(e.getMessage(), "CON_APP_EVT_KEY")) {
                            retryOnConstraintViolationException(consumerKey, revocationTime, organization,
                                    retryAttemptCounter, e);
                        } else {
                            throw new IdentityOAuth2Exception("Error while inserting consumer key event revocation "
                                    + "rule to db." + e.getMessage(), e);
                        }
                    } catch (Exception e) {
                        rollbackConsumerAppEventTransaction(connection);
                        // Handle constrain violation issue in JDBC drivers which does not throw
                        // SQLIntegrityConstraintViolationException or SQLException.
                        if (StringUtils.containsIgnoreCase(e.getMessage(), "CON_APP_EVT_KEY") || (e.getCause() != null
                                && StringUtils.containsIgnoreCase(e.getCause().getMessage(), "CON_APP_EVT_KEY"))
                                || (e.getCause() != null && e.getCause().getCause() != null &&
                                StringUtils.containsIgnoreCase(e.getCause().getCause().getMessage(),
                                        "CON_APP_EVT_KEY"))) {
                            retryOnConstraintViolationException(consumerKey, revocationTime, organization,
                                    retryAttemptCounter, e);
                        } else {
                            throw new IdentityOAuth2Exception("Error while inserting user event revocation rule to db."
                                    + e.getMessage(), e);
                        }
                    }
                } else {
                    log.debug("Consumer key event token revocation rule updated.");
                    IdentityDatabaseUtil.commitTransaction(connection);
                }
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception("Error while inserting consumer key event revocation rule to db."
                        + e.getMessage(), e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while inserting consumer key event revocation rule to db."
                    + e.getMessage(), e);
        }
    }

    /**
     * Retry the consumer app event token revocation event persisting transaction on constraint violation exception.
     *
     * @param consumerKey         Consumer key
     * @param revocationTime      Revocation time
     * @param organization        Organization
     * @param retryAttemptCounter Retry attempt counter
     * @param exception           Constraint Violation Exception
     * @throws IdentityOAuth2Exception If maximum retry count exceeds
     */
    private void retryOnConstraintViolationException(String consumerKey, long revocationTime, String organization,
                                                     int retryAttemptCounter, Exception exception)
            throws IdentityOAuth2Exception {

        String errorMessage = String.format("Consumer app event token revocation rule for consumer key : %s"
                + "and organization : %s already exists", consumerKey, organization);
        if (retryAttemptCounter >= getTokenPersistRetryCount()) {
            log.error("'CON_APP_EVT_KEY' constrain violation retry count exceeds the maximum");
            throw new IdentityOAuth2Exception(errorMessage, exception);
        }
        revokeTokensByConsumerKeyEvent(consumerKey, revocationTime, organization,
                retryAttemptCounter + 1);
    }

    /**
     * Rollback the consumer app event token revocation event persisting transaction.
     *
     * @param connection Connection
     */
    private void rollbackConsumerAppEventTransaction(Connection connection) {

        log.warn("Consumer key event token revocation rule already persisted.");
        IdentityDatabaseUtil.rollbackTransaction(connection);
    }


    /**
     * Get the maximum number of retries for token persistence.
     *
     * @return Maximum number of retries for token persistence.
     */
    private int getTokenPersistRetryCount() {

        int tokenPersistRetryCount = DEFAULT_TOKEN_PERSIST_RETRY_COUNT;
        if (getProperty(OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT) != null) {
            tokenPersistRetryCount = Integer.parseInt(getProperty(OAUTH_TOKEN_PERSISTENCE_RETRY_COUNT));
        }
        if (log.isDebugEnabled()) {
            log.debug("OAuth Token Persistence Retry count set to " + tokenPersistRetryCount);
        }
        return tokenPersistRetryCount;
    }
}
