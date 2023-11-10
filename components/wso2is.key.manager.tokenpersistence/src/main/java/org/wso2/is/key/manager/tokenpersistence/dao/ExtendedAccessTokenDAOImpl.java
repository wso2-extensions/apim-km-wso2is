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

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAOImpl;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;

/**
 * An extension for AccessTokenDAOImpl when handling non-persistent access/refresh tokens.
 */

public class ExtendedAccessTokenDAOImpl extends AccessTokenDAOImpl {

    private static final Log log = LogFactory.getLog(ExtendedAccessTokenDAOImpl.class);

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
    public void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState, String consumerKey,
                                                  String tokenStateId, AccessTokenDO accessTokenDO,
                                                  String userStoreDomain) {

    }

    @Override
    public void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState, String consumerKey,
                                                  String tokenStateId, AccessTokenDO accessTokenDO,
                                                  String userStoreDomain, String grantType)
            throws IdentityOAuth2Exception {

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

    /**
     * Checks if the provided access token is invalid. An access token is considered invalid if its token state is one
     * of 'INACTIVE', 'REVOKED', or 'EXPIRED'.
     *
     * @param accessTokenIdentifier The unique identifier of the access token.
     * @return {@code true} if the access token is invalid, {@code false} otherwise.
     * @throws IdentityOAuth2Exception If an error occurs while checking the token's validity.
     */
    public boolean isInvalidToken(String accessTokenIdentifier) throws IdentityOAuth2Exception {

        String sql = SQLQueries.IS_INVALID_LEGACY_TOKEN;
        sql = OAuth2Util.getTokenPartitionedSqlByToken(sql, accessTokenIdentifier);
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
            preparedStatement.setString(1, getHashingPersistenceProcessor()
                    .getProcessedAccessTokenIdentifier(accessTokenIdentifier));
            preparedStatement.setString(2, getHashingPersistenceProcessor()
                    .getProcessedAccessTokenIdentifier(accessTokenIdentifier));
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                return resultSet.next();
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while checking state of token as an invalid token.", e);
        }
    }


    /**
     * Get migrated access tokens (JWT) for the given client and user which either in ACTIVE or EXPIRED state
     * if requested.
     *
     * @param consumerKey       Client key
     * @param authenticatedUser Authenticated user
     * @param userStoreDomain   User store domain
     * @param includeExpired    Include expired tokens
     * @return Set of access tokens
     * @throws IdentityOAuth2Exception If an error occurs while retrieving access tokens
     */
    Set<AccessTokenDO> getMigratedAccessTokens(String consumerKey, AuthenticatedUser authenticatedUser,
                                               String userStoreDomain, boolean includeExpired)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving access tokens for client: " + consumerKey + " user: " + authenticatedUser.toString());
        }

        String tenantDomain = getUserResidentTenantDomain(authenticatedUser);
        String tenantAwareUsernameWithNoUserDomain = authenticatedUser.getUserName();
        String userDomain = OAuth2Util.getUserStoreDomain(authenticatedUser);
        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        boolean isUsernameCaseSensitive
                = IdentityUtil.isUserStoreCaseSensitive(authenticatedUser.getUserStoreDomain(), tenantId);
        userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStoreDomain);
        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(authenticatedUser);

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Map<String, AccessTokenDO> accessTokenDOMap = new HashMap<>();
        try {
            String sql;

            if (includeExpired) {
                if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                    sql = org.wso2.carbon.identity.oauth2.dao.SQLQueries
                            .RETRIEVE_ACTIVE_EXPIRED_ACCESS_TOKEN_BY_CLIENT_ID_USER_IDP_NAME;
                } else {
                    sql = org.wso2.carbon.identity.oauth2.dao.SQLQueries
                            .RETRIEVE_ACTIVE_EXPIRED_ACCESS_TOKEN_BY_CLIENT_ID_USER;
                }
            } else {
                if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                    sql = org.wso2.carbon.identity.oauth2.dao.SQLQueries
                            .RETRIEVE_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER_IDP_NAME;
                } else {
                    sql = org.wso2.carbon.identity.oauth2.dao.SQLQueries
                            .RETRIEVE_ACTIVE_ACCESS_TOKEN_BY_CLIENT_ID_USER;
                }
            }

            sql = OAuth2Util.getTokenPartitionedSqlByUserStore(sql, userStoreDomain);

            if (!isUsernameCaseSensitive) {
                sql = sql.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
            }

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, getPersistenceProcessor().getProcessedClientId(consumerKey));
            int appTenantId = IdentityTenantUtil.getLoginTenantId();
            prepStmt.setInt(2, appTenantId);
            if (isUsernameCaseSensitive) {
                prepStmt.setString(3, tenantAwareUsernameWithNoUserDomain);
            } else {
                prepStmt.setString(3, tenantAwareUsernameWithNoUserDomain.toLowerCase());
            }
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, userDomain);
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                prepStmt.setString(6, authenticatedIDP);
                // Set tenant ID of the IDP by considering it is same as appTenantID.
                prepStmt.setInt(7, appTenantId);
            }

            resultSet = prepStmt.executeQuery();

            while (resultSet.next()) {
                String accessToken = getPersistenceProcessor()
                        .getPreprocessedAccessTokenIdentifier(resultSet.getString(1));
                if (accessTokenDOMap.get(accessToken) == null) {
                    String refreshToken = getPersistenceProcessor().getPreprocessedRefreshToken(resultSet.getString(2));
                    Timestamp issuedTime = resultSet.getTimestamp(3, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                    Timestamp refreshTokenIssuedTime = resultSet.getTimestamp(4, Calendar.getInstance(TimeZone
                            .getTimeZone(UTC)));
                    long validityPeriodInMillis = resultSet.getLong(5);
                    long refreshTokenValidityPeriodMillis = resultSet.getLong(6);
                    String tokenType = resultSet.getString(7);
                    String[] scope = OAuth2Util.buildScopeArray(resultSet.getString(8));
                    String tokenId = resultSet.getString(9);
                    String subjectIdentifier = resultSet.getString(10);
                    String tokenBindingReference = resultSet.getString(11);
                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(tenantAwareUsernameWithNoUserDomain,
                            userDomain, tenantDomain, authenticatedIDP);
                    ServiceProvider serviceProvider;
                    try {
                        serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                                getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
                    } catch (IdentityApplicationManagementException e) {
                        throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data " +
                                "for client id " + consumerKey, e);
                    }
                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);
                    AccessTokenDO dataDO = new AccessTokenDO(consumerKey, user, scope, issuedTime,
                            refreshTokenIssuedTime, validityPeriodInMillis,
                            refreshTokenValidityPeriodMillis, tokenType);
                    dataDO.setAccessToken(accessToken);
                    dataDO.setRefreshToken(refreshToken);
                    dataDO.setTokenId(tokenId);
                    if (StringUtils.isNotBlank(tokenBindingReference) && !NONE.equals(tokenBindingReference)) {
                        setTokenBindingToAccessTokenDO(dataDO, connection, tokenId);
                    }
                    accessTokenDOMap.put(accessToken, dataDO);
                } else {
                    String scope = resultSet.getString(8).trim();
                    AccessTokenDO accessTokenDO = accessTokenDOMap.get(accessToken);
                    accessTokenDO.setScope((String[]) ArrayUtils.add(accessTokenDO.getScope(), scope));
                }
            }
        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'ACTIVE' access tokens for " +
                    "Client ID : " + consumerKey + " and User ID : " + authenticatedUser;
            if (includeExpired) {
                errorMsg = errorMsg.replace("ACTIVE", "ACTIVE or EXPIRED");
            }
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        return new HashSet<>(accessTokenDOMap.values());
    }
}
