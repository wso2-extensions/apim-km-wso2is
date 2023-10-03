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
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAOImpl;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Map;

/**
 * Util class to handle opaque tokens. This is provided to handle backward compatibility
 * related usecases
 */
public class OpaqueTokenUtil {

    private static final Log log = LogFactory.getLog(OpaqueTokenUtil.class);
    public static final String ACCESS_TOKEN_IS_NOT_ACTIVE_ERROR_MESSAGE = "Invalid Access Token. Access token is " +
            "not ACTIVE.";

    /**
     * Differentiate default token issuers from all available token issuers map.
     *
     * @param allOAuthTokenIssuerMap     Map of all available token issuers.
     * @param defaultOAuthTokenIssuerMap default token issuers
     */
    private static void extractDefaultOauthTokenIssuers(Map<String, OauthTokenIssuer> allOAuthTokenIssuerMap,
                                                        Map<String, OauthTokenIssuer> defaultOAuthTokenIssuerMap) {

        defaultOAuthTokenIssuerMap.put(OAuthServerConfiguration.JWT_TOKEN_TYPE,
                allOAuthTokenIssuerMap.get(OAuthServerConfiguration.JWT_TOKEN_TYPE));
        allOAuthTokenIssuerMap.remove(OAuthServerConfiguration.JWT_TOKEN_TYPE);

        defaultOAuthTokenIssuerMap.put(OAuthServerConfiguration.DEFAULT_TOKEN_TYPE,
                allOAuthTokenIssuerMap.get(OAuthServerConfiguration.DEFAULT_TOKEN_TYPE));
        allOAuthTokenIssuerMap.remove(OAuthServerConfiguration.DEFAULT_TOKEN_TYPE);
    }

    /**
     * Loop through provided token issuer list and tries to get the access token DO.
     *
     * @param tokenIdentifier Provided token identifier.
     * @param tokenIssuerMap  List of token issuers.
     * @return Obtained matching access token DO if possible.
     * @throws IdentityOAuth2Exception
     */
    private static AccessTokenDO getAccessTokenDOFromMatchingTokenIssuer(String tokenIdentifier,
                                                                         Map<String, OauthTokenIssuer> tokenIssuerMap,
                                                                         boolean includeExpired)
            throws IdentityOAuth2Exception {

        AccessTokenDO accessTokenDO;
        if (tokenIssuerMap != null) {
            for (Map.Entry<String, OauthTokenIssuer> oauthTokenIssuerEntry : tokenIssuerMap.entrySet()) {
                try {
                    OauthTokenIssuer oauthTokenIssuer = oauthTokenIssuerEntry.getValue();
                    String tokenAlias = oauthTokenIssuer.getAccessTokenHash(tokenIdentifier);
                    if (oauthTokenIssuer.usePersistedAccessTokenAlias()) {
                        accessTokenDO = getAccessTokenDOFromTokenIdentifier(tokenAlias, includeExpired);
                    } else {
                        accessTokenDO = getAccessTokenDOFromTokenIdentifier(tokenIdentifier, includeExpired);
                    }
                    return accessTokenDO;
                } catch (OAuthSystemException e) {
                    if (log.isDebugEnabled()) {
                        if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                            log.debug("Token issuer: " + oauthTokenIssuerEntry.getKey() + " was tried and" +
                                    " failed to parse the received token: " + tokenIdentifier);
                        } else {
                            log.debug("Token issuer: " + oauthTokenIssuerEntry.getKey() + " was tried and" +
                                    " failed to parse the received token.");
                        }
                    }
                } catch (IllegalArgumentException e) {
                    if (log.isDebugEnabled()) {
                        if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                            log.debug("Token issuer: " + oauthTokenIssuerEntry.getKey() + " was tried and"
                                    + " failed to get the token from database: " + tokenIdentifier);
                        } else {
                            log.debug("Token issuer: " + oauthTokenIssuerEntry.getKey() + " was tried and"
                                    + " failed  to get the token from database.");
                        }
                    }
                }
            }
        }
        return null;
    }

    private static AccessTokenDO getAccessTokenDOFromTokenIdentifier(String accessTokenIdentifier,
                                                                     boolean includeExpired)
            throws IdentityOAuth2Exception {

        boolean cacheHit = false;
        AccessTokenDO accessTokenDO = null;

        // As the server implementation knows about the PersistenceProcessor Processed Access Token,
        // we are converting before adding to the cache.
        // String processedToken = OAuth2Util.getPersistenceProcessor()
        // .getProcessedAccessTokenIdentifier(accessTokenIdentifier);

        // check the cache, if caching is enabled.
        OAuthCacheKey cacheKey = new OAuthCacheKey(accessTokenIdentifier);
        CacheEntry result = OAuthCache.getInstance().getValueFromCache(cacheKey);
        // cache hit, do the type check.
        if (result != null && result instanceof AccessTokenDO) {
            accessTokenDO = (AccessTokenDO) result;
            cacheHit = true;
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Hit OAuthCache for accessTokenIdentifier: " + accessTokenIdentifier);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Hit OAuthCache with accessTokenIdentifier");
                }
            }
        }
        // cache miss, load the access token info from the database.
        if (accessTokenDO == null) {
            accessTokenDO = new AccessTokenDAOImpl().getAccessToken(accessTokenIdentifier, includeExpired);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Retrieved active access token from OAuthCache for token Identifier: "
                        + accessTokenDO.getTokenId());
            }
        }
        if (accessTokenDO == null) {
            // this means the token is not active so we can't proceed further
            throw new IllegalArgumentException(ACCESS_TOKEN_IS_NOT_ACTIVE_ERROR_MESSAGE);
        }
        // Add the token back to the cache in the case of a cache miss but don't add to cache when OAuth2 token
        // hashing feature enabled inorder to reduce the complexity.
        if (!cacheHit && OAuth2Util.isHashDisabled()) {
            OAuthCache.getInstance().addToCache(cacheKey, accessTokenDO);
            if (log.isDebugEnabled()) {
                log.debug("Access Token Info object was added back to the cache.");
            }
        }
        return accessTokenDO;
    }

    /**
     * Validate opaque refresh token and return the validation data object.
     *
     * @param tokenReqMessageContext Token request message context.
     * @return RefreshTokenValidationDataDO  Refresh token validation data object.
     * @throws IdentityOAuth2Exception if an error occurs while validating the refresh token.
     */

    public static RefreshTokenValidationDataDO validateOpaqueRefreshToken(
            OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = validateRefreshToken(tokenReq.getClientId(),
                tokenReq.getRefreshToken());
        if (validationBean.getAccessToken() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid Refresh Token provided for Client with Client Id : " + tokenReq.getClientId());
            }
            throw new IdentityOAuth2Exception("Persisted access token data not found");
        }
        return validationBean;
    }

    /**
     * Validate opaque refresh token from database and return the validation data object.
     *
     * @param clientId     Client Id
     * @param refreshToken Refresh token
     * @return RefreshTokenValidationDataDO  Refresh token validation data object.
     * @throws IdentityOAuth2Exception if an error occurs while validating the refresh token.
     */
    private static RefreshTokenValidationDataDO validateRefreshToken(String clientId, String refreshToken)
            throws IdentityOAuth2Exception {

        return OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                .validateRefreshToken(clientId, refreshToken);
    }
}
