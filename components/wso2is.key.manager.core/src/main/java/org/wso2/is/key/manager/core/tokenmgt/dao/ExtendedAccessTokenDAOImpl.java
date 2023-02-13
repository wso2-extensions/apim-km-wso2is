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

package org.wso2.is.key.manager.core.tokenmgt.dao;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.HashingPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.SQLQueries;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;

/**
 * An extension for AccessTokenDAOImpl when handling non-persistent access/refresh tokens.
 */
public class ExtendedAccessTokenDAOImpl implements AccessTokenDAO {

    private static final Log log = LogFactory.getLog(ExtendedAccessTokenDAOImpl.class);
    private TokenPersistenceProcessor persistenceProcessor, hashingPersistenceProcessor;

    public ExtendedAccessTokenDAOImpl() {
        persistenceProcessor = createPersistenceProcessor();
        hashingPersistenceProcessor = new HashingPersistenceProcessor();
    }

    private TokenPersistenceProcessor createPersistenceProcessor() {
        try {
            return OAuthServerConfiguration.getInstance().getPersistenceProcessor();
        } catch (IdentityOAuth2Exception e) {
            log.error("Error retrieving TokenPersistenceProcessor. Defaulting to PlainTextProcessor", e);
            return new PlainTextPersistenceProcessor();
        }
    }

    /**
     * Method to get HashingPersistenceProcessor instance
     * @return an instance of HashingPersistenceProcessor
     */
    private TokenPersistenceProcessor getHashingPersistenceProcessor() {

        return hashingPersistenceProcessor;
    }

    private TokenPersistenceProcessor getPersistenceProcessor() {

        return persistenceProcessor;
    }

    @Override
    public void insertAccessToken(String accessToken, String consumerKey, AccessTokenDO accessTokenDO,
                                  String userStoreDomain) {
        //do nothing
    }

    @Override
    public boolean insertAccessToken(String accessToken, String consumerKey, AccessTokenDO newAccessTokenDO,
                                     AccessTokenDO existingAccessTokenDO, String rawUserStoreDomain) {
        //do nothing
        return true;
    }

    @Override
    public void updateAccessTokenState(String tokenId, String tokenState, String grantType) {
        // do-nothing
    }

    @Override
    public Set<String> getTokenIdBySessionIdentifier(String sessionId) {
        return new HashSet<>();
    }

    @Override
    public void storeTokenToSessionMapping(String sessionContextIdentifier, String tokenId, int tenantId) {
        //do nothing
    }

    @Override
    public Set<AccessTokenDO> getAccessTokens(String consumerKey, AuthenticatedUser userName, String userStoreDomain,
                                              boolean includeExpired) {
        return new HashSet<>();
    }

    @Override
    public AccessTokenDO getAccessToken(String accessTokenIdentifier, boolean includeExpired) {
        //only the jti is received at this point as the identifier
        //skip if token included in the database as a revoked token
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setTokenId(accessTokenIdentifier);

        return accessTokenDO;
    }

    @Override
    public Set<String> getAccessTokensByUser(AuthenticatedUser authenticatedUser) {
        //no jtis to return, hence best option to return empty set
        return new HashSet<>();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByUserForOpenidScope(AuthenticatedUser authenticatedUser) {
        return new HashSet<>();
    }


    @Override
    public Set<AccessTokenDO> getAccessTokensByTenant(int tenantId) {
        return new HashSet<>();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensOfUserStore(int tenantId, String userStoreDomain) {
        return new HashSet<>();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByBindingRef(AuthenticatedUser user, String bindingRef) {
        return new HashSet<>();
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByBindingRef(String bindingRef) {
        return new HashSet<>();
    }

    @Override
    public String getAccessTokenByTokenId(String tokenId) {
        return null;
    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String consumerKey) {
        return new HashSet<>();
    }

    @Override
    public Set<AccessTokenDO> getActiveAcessTokenDataByConsumerKey(String consumerKey) {
        return new HashSet<>();
    }

    @Override
    public Set<AccessTokenDO> getActiveTokenSetWithTokenIdByConsumerKeyForOpenidScope(String consumerKey) {
        return new HashSet<>();
    }

    @Override
    public String getTokenIdByAccessToken(String token) {
        return null;
    }

    @Override
    public AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain,
                                              String scope, boolean includeExpiredTokens) {
        return null;
    }

    @Override
    public List<AccessTokenDO> getLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser,
                                                     String userStoreDomain, String scope, boolean includeExpiredTokens,
                                                     int limit) {
        return new ArrayList<>();
    }

    @Override
    public AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser,
                                              String userStoreDomain, String scope, String tokenBindingReference,
                                              boolean includeExpiredTokens) {

        return null;
    }

    @Override
    public void revokeAccessTokens(String[] tokens) throws IdentityOAuth2Exception {
    }

    @Override
    public void revokeAccessTokensInBatch(String[] tokens) throws IdentityOAuth2Exception {
    }

    @Override
    public void revokeAccessTokensIndividually(String[] tokens) throws IdentityOAuth2Exception {
    }

    @Override
    public void revokeAccessTokens(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {
    }

    @Override
    public void revokeAccessTokensInBatch(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {
    }

    @Override
    public void revokeAccessTokensIndividually(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {
    }

    @Override
    public void revokeAccessToken(String tokenId, String userId) {

    }

    @Override
    public void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState, String consumerKey,
                                                  String tokenStateId, AccessTokenDO accessTokenDO,
                                                  String userStoreDomain) {

    }

    @Override
    public void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState, String consumerKey,
                                                  String tokenStateId, AccessTokenDO accessTokenDO,
                                                  String userStoreDomain, String grantType)
            throws IdentityOAuth2Exception {

        if (OAuthConstants.GrantTypes.REFRESH_TOKEN.equals(grantType)
                && OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE.equals(tokenState)) {
            //store invalidated refresh token as a new entry
            if (accessTokenDO.getRefreshToken() == null) {
                throw new IdentityOAuth2Exception("Refresh token is not available");
            }
            //TODO:// no access token information ATM
            accessTokenDO.setAccessToken("DEFAULT");
            insertInvalidToken(accessTokenDO, consumerKey);
        } else if (OAuthConstants.TokenStates.TOKEN_STATE_REVOKED.equals(tokenState) && grantType == null) {
            //store revoked access token or refresh token as a new entry
            if (accessTokenDO.getAccessToken() == null && accessTokenDO.getRefreshToken() == null) {
                throw new IdentityOAuth2Exception("Access token/Refresh token not available");
            }
            if (accessTokenDO.getAccessToken() != null && accessTokenDO.getRefreshToken() == null) {
                //TODO://no refresh token information ATM
                accessTokenDO.setRefreshToken("DEFAULT");
            }
            if (accessTokenDO.getRefreshToken() != null && accessTokenDO.getAccessToken() == null) {
                //TODO://no access token information ATM
                accessTokenDO.setAccessToken("DEFAULT");
            }
            insertInvalidToken(accessTokenDO, consumerKey);
        }
    }
    @Override
    public void updateUserStoreDomain(int tenantId, String currentUserStoreDomain, String newUserStoreDomain) {

    }

    @Override
    public void updateTokenIsConsented(String tokenId, boolean isConsentedGrant) {

    }

    @Override
    public void updateAccessTokenState(String tokenId, String tokenState) {

    }

    @Override
    public String getName() {
        return "ExtendedAccessTokenDAOImpl";
    }

    private void insertInvalidToken(AccessTokenDO accessTokenDO, String consumerKey)
            throws IdentityOAuth2Exception {

        String userDomain = OAuth2Util.getUserStoreDomain(accessTokenDO.getAuthzUser());
        String sql;
        if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
            if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                //TODO: check if getTokenPartitionedSqlByToken is needed
                sql = SQLQueries.INSERT_OAUTH2_ACCESS_TOKEN_WITH_IDP_NAME_WITH_CONSENTED_TOKEN;
            } else {
                sql = SQLQueries.INSERT_OAUTH2_ACCESS_TOKEN_WITH_IDP_NAME;
            }
        } else {
            if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                sql = SQLQueries.INSERT_OAUTH2_ACCESS_TOKEN_WITH_CONSENTED_TOKEN;
            } else {
                sql = SQLQueries.INSERT_OAUTH2_ACCESS_TOKEN;
            }
        }
        sql = OAuth2Util.getTokenPartitionedSqlByUserStore(sql, userDomain);
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(sql)) {
                prepStmt.setString(1, getPersistenceProcessor().getProcessedAccessTokenIdentifier(
                        accessTokenDO.getAccessToken()));
                prepStmt.setString(2,  getPersistenceProcessor().getProcessedRefreshToken(
                        accessTokenDO.getRefreshToken()));
                prepStmt.setString(3, accessTokenDO.getAuthzUser().getUserName());
                int tenantId = OAuth2Util.getTenantId(accessTokenDO.getAuthzUser().getTenantDomain());
                prepStmt.setInt(4, tenantId);
                prepStmt.setString(5, OAuth2Util.getSanitizedUserStoreDomain(userDomain));
                if (accessTokenDO.getIssuedTime() == null) {
                    //TODO://when persisting refresh token access token information is not available, hence persist the
                    //same refresh token issued time. This has no impact
                    prepStmt.setTimestamp(6, accessTokenDO.getRefreshTokenIssuedTime(),
                            Calendar.getInstance(TimeZone.getTimeZone("UTC")));
                } else {
                    prepStmt.setTimestamp(6, accessTokenDO.getIssuedTime(),
                            Calendar.getInstance(TimeZone.getTimeZone("UTC")));
                }
                if (accessTokenDO.getRefreshTokenIssuedTime() == null) {
                    //TODO://when persisting access token, refresh token information is not available, hence persist the
                    //same access token issued time. This has no impact
                    prepStmt.setTimestamp(7, accessTokenDO.getIssuedTime(), Calendar.getInstance(TimeZone
                            .getTimeZone("UTC")));
                } else {
                    prepStmt.setTimestamp(7, accessTokenDO.getRefreshTokenIssuedTime(), Calendar.getInstance(TimeZone
                            .getTimeZone("UTC")));
                }
                prepStmt.setLong(8, accessTokenDO.getValidityPeriodInMillis());
                prepStmt.setLong(9, accessTokenDO.getRefreshTokenValidityPeriodInMillis());
                prepStmt.setString(10, OAuth2Util.hashScopes(accessTokenDO.getScope()));
                prepStmt.setString(11, accessTokenDO.getTokenState());
                prepStmt.setString(12, accessTokenDO.getTokenType());
                prepStmt.setString(13, accessTokenDO.getTokenId());
                prepStmt.setString(14, accessTokenDO.getGrantType());
                prepStmt.setString(15, accessTokenDO.getAuthzUser().getAuthenticatedSubjectIdentifier());
                prepStmt.setString(16, getHashingPersistenceProcessor()
                        .getProcessedAccessTokenIdentifier(accessTokenDO.getAccessToken()));
                prepStmt.setString(17,
                        hashingPersistenceProcessor.getProcessedRefreshToken(accessTokenDO.getRefreshToken()));
                boolean tokenBindingAvailable = isTokenBindingAvailable(accessTokenDO.getTokenBinding());
                if (tokenBindingAvailable) {
                    prepStmt.setString(18, accessTokenDO.getTokenBinding().getBindingReference());
                } else {
                    //TODO://default behavior for non persistence token scenario
                    prepStmt.setString(18, NONE);
                }
                if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                    String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(accessTokenDO.getAuthzUser());
                    if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                        prepStmt.setString(19, Boolean.toString(accessTokenDO.isConsentedToken()));
                        prepStmt.setString(20, authenticatedIDP);
                        prepStmt.setInt(21, tenantId);
                        prepStmt.setString(22, getPersistenceProcessor().getProcessedClientId(consumerKey));
                    } else {
                        prepStmt.setString(19, authenticatedIDP);
                        prepStmt.setInt(20, tenantId);
                        prepStmt.setString(21, getPersistenceProcessor().getProcessedClientId(consumerKey));
                    }
                } else {
                    if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                        prepStmt.setString(19, Boolean.toString(accessTokenDO.isConsentedToken()));
                        prepStmt.setString(20, getPersistenceProcessor().getProcessedClientId(consumerKey));
                    } else {
                        prepStmt.setString(19, getPersistenceProcessor().getProcessedClientId(consumerKey));
                    }
                }
                prepStmt.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);
                //TODO:// Not storing any token binding information
                //TODO:// Not storing scope data to IDN_OAUTH2_ACCESS_TOKEN_SCOPE
                //TODO:// No con app key violation. Hence not explicitly handling it
            } catch (SQLException e) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityOAuth2Exception("Error occurred while adding invalid refresh token", e);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error occurred while adding invalid refresh token", e);
        }
        //skip token scope and binding table updates
    }

    /**
     * Check whether a valid access token binding available.
     *
     * @param tokenBinding token binding.
     * @return true if valid binding available.
     */
    private boolean isTokenBindingAvailable(TokenBinding tokenBinding) {

        return tokenBinding != null && StringUtils.isNotBlank(tokenBinding.getBindingType()) && StringUtils
                .isNotBlank(tokenBinding.getBindingReference()) && StringUtils
                .isNotBlank(tokenBinding.getBindingValue());
    }

    public boolean isInvalidToken(String accessToken) throws IdentityOAuth2Exception {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            String sql = OAuth2Util.getTokenPartitionedSqlByToken(SQLConstants.IS_INVALID_ACCESS_TOKEN, accessToken);
            try (PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
                preparedStatement.setString(1, getHashingPersistenceProcessor().getProcessedRefreshToken(accessToken));
                try (ResultSet resultSet = preparedStatement.executeQuery()) {
                    return resultSet.next();
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while checking existence of token as an invalid token.", e);
        }
    }
}
