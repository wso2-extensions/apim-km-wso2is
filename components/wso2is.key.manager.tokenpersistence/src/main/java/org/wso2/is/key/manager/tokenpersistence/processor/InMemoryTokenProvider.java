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
package org.wso2.is.key.manager.tokenpersistence.processor;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenProvider;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.is.key.manager.tokenpersistence.PersistenceConstants;
import org.wso2.is.key.manager.tokenpersistence.utils.OpaqueTokenUtil;
import org.wso2.is.key.manager.tokenpersistence.utils.TokenMgtUtil;

import java.sql.Timestamp;
import java.util.Optional;

/**
 * In Memory token validation processor for in memory token persistence. Token Validation processor is supposed to be
 * used during token introspection and user info endpoints where you need to validate the token before proceeding.
 */
public class InMemoryTokenProvider implements TokenProvider {

    private static final Log log = LogFactory.getLog(InMemoryTokenProvider.class);

    public AccessTokenDO getVerifiedAccessToken(String token, boolean includeExpired)
            throws IdentityOAuth2Exception {

        AccessTokenDO validationDataDO;
        // check if token is JWT.
        TokenMgtUtil.isJWTToken(token);
        log.debug(String.format("Validating JWT Token with expiry %s", includeExpired));
        // validate JWT token signature, expiry time, not before time.
        SignedJWT signedJWT = TokenMgtUtil.parseJWT(token);
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet);
        String consumerKey = (String) claimsSet.getClaim(PersistenceConstants.AUTHORIZATION_PARTY);
        String accessTokenIdentifier = TokenMgtUtil.getTokenIdentifier(claimsSet);
        // expiry time verification.
        boolean isTokenActive = true;
        if (!TokenMgtUtil.isActive(claimsSet.getExpirationTime())) {
            if (!includeExpired) {
                TokenMgtUtil.removeTokenFromCache(accessTokenIdentifier, consumerKey);
                throw new IdentityOAuth2Exception("Invalid token. Expiry time exceeded.");
            }
            isTokenActive = false;
        }
        // not before time verification.
        TokenMgtUtil.checkNotBeforeTime(claimsSet.getNotBeforeTime());
        /*
         * check whether the token is already revoked through direct revocations and following indirect
         * revocations.
         * 1. check if consumer app was changed.
         * 2. check if user was changed.
         */
        if (TokenMgtUtil.isTokenRevokedDirectly(accessTokenIdentifier, consumerKey)
                || TokenMgtUtil.isTokenRevokedIndirectly(claimsSet)) {
            throw new IllegalArgumentException("Invalid Access Token. ACTIVE access token is not found.");
        }
        Optional<AccessTokenDO> accessTokenDO = TokenMgtUtil.getTokenDOFromCache(accessTokenIdentifier);
        if (accessTokenDO.isPresent()) {
            validationDataDO = accessTokenDO.get();
            if (log.isDebugEnabled()) {
                log.debug("Retrieved active access token from OAuthCache for token Identifier: "
                        + validationDataDO.getTokenId());
            }
            if (!isTokenActive) {
                TokenMgtUtil.removeTokenFromCache(accessTokenIdentifier, consumerKey);
            }
        } else {
            // create new AccessTokenDO with validated token information.
            validationDataDO = new AccessTokenDO();
            validationDataDO.setAccessToken(accessTokenIdentifier);
            validationDataDO.setConsumerKey(consumerKey);
            validationDataDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
            validationDataDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                    - claimsSet.getIssueTime().getTime());
            Object scopes = claimsSet.getClaim(PersistenceConstants.SCOPE);
            validationDataDO.setScope(TokenMgtUtil.getScopes(scopes));
            AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
            validationDataDO.setAuthzUser(authenticatedUser);
            if (isTokenActive) {
                validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            } else {
                validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
            }
            // TODO:// need to decide how to determine the consented state for the previous access token or if previous

            // Add the token back to the cache in the case of a cache miss.
            TokenMgtUtil.addTokenToCache(accessTokenIdentifier, validationDataDO);
        }
        return validationDataDO;
    }


    @Override
    public RefreshTokenValidationDataDO getVerifiedRefreshToken(String token, String consumerKey)
            throws IdentityOAuth2Exception {
                RefreshTokenValidationDataDO validationDataDO = null;
        if (!OAuth2Util.isJWT(token)) {
            log.debug("Refresh token is not a JWT. Hence, validating as an opaque token from database.");
            // For backward compatibility, we check whether it is available in idn_oauth2_token table.
            RefreshTokenValidationDataDO validationDO = OpaqueTokenUtil.validateOpaqueRefreshToken(token, consumerKey);
            OAuthUtil.clearOAuthCache(consumerKey, validationDO.getAuthorizedUser(),
                    OAuth2Util.buildScopeString(validationDO.getScope()), "NONE");
            return validationDO;
        }
        SignedJWT signedJWT = TokenMgtUtil.parseJWT(token);
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet);
        String consumerKeyFromToken = (String) claimsSet.getClaim(PersistenceConstants.AUTHORIZATION_PARTY);
        // validate consumer key in the request against the token.
        if (!consumerKey.equals(consumerKeyFromToken)) {
            throw new IdentityOAuth2Exception("Invalid refresh token. Consumer key does not match.");
        }
        /*
         * check whether the token is not already revoked through direct revocations and following indirect
         * revocations.
         * 1. check if consumer app was changed.
         * 2. check if user was changed.
         */
        if (!TokenMgtUtil.isTokenRevokedDirectly(token, consumerKey)
                && !TokenMgtUtil.isTokenRevokedIndirectly(claimsSet)) {
            validationDataDO = new RefreshTokenValidationDataDO();
            // set expiration state according to jwt claim in it.
            if (TokenMgtUtil.isActive(claimsSet.getExpirationTime())) {
                validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            } else {
                validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
            }
            // set other fields from jwt claims.
            validationDataDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
            validationDataDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                    - claimsSet.getIssueTime().getTime());
            validationDataDO.setScope(TokenMgtUtil.getScopes(claimsSet.getClaim(PersistenceConstants.SCOPE)));
            AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
            validationDataDO.setAuthorizedUser(authenticatedUser);
        }
        return validationDataDO;
    }
}
