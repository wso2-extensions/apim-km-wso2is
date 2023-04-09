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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * An extension for AccessTokenDAOImpl when handling non-persistent access/refresh tokens.
 */

public class ExtendedAccessTokenDAOImpl implements AccessTokenDAO {


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
            //insertInvalidToken(accessTokenDO, consumerKey);
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
            //insertInvalidToken(accessTokenDO, consumerKey);
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
/*
    public boolean isInvalidToken(String accessToken) throws IdentityOAuth2Exception {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            String query = "SELECT 1 FROM IDN_OAUTH2_ACCESS_TOKEN "
                    + "WHERE ACCESS_TOKEN_HASH = ? AND (TOKEN_STATE='INACTIVE' OR"
                    + " TOKEN_STATE='REVOKED')";
            String sql = OAuth2Util.getTokenPartitionedSqlByToken(query, accessToken);
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
*/
}
