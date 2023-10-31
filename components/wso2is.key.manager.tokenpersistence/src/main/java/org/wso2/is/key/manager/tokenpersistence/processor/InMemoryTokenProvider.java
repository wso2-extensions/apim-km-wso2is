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
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
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
 * Token Validation processor is supposed to be used during token introspection and user info endpoints where you need
 * to validate the token before proceeding. This class provides methods for validating access tokens and refresh tokens
 * in the context of in-memory token persistence. It implements the TokenProvider interface to offer the following
 * functionalities:
 * - Validating access tokens, including JWT tokens, checking their expiration, signature, and revocation status.
 * - Validating refresh tokens, including JWT tokens, and checking their expiration and revocation status.
 * The class also handles the caching of validated tokens for improved performance.
 */
public class InMemoryTokenProvider implements TokenProvider {

    private static final Log log = LogFactory.getLog(InMemoryTokenProvider.class);

    @Override
    public AccessTokenDO getVerifiedAccessToken(String token, boolean includeExpired) throws IdentityOAuth2Exception {

        AccessTokenDO validationDataDO = null;
        // check if token is JWT.
        TokenMgtUtil.isJWTToken(token);
        // validate JWT token signature, expiry time, not before time.
        SignedJWT signedJWT = TokenMgtUtil.parseJWT(token);
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        if (!TokenMgtUtil.isRefreshTokenType(claimsSet)) {
            TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet);
            // No need to validate the consumer key in the token with the consumer key in the verification request, as
            // it is done by the calling functions.
            String consumerKey = (String) claimsSet.getClaim(PersistenceConstants.JWTClaim.AUTHORIZATION_PARTY);
            String accessTokenIdentifier = TokenMgtUtil.getTokenIdentifier(claimsSet);
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug(String.format("Validating JWT Token: %s with expiry: %s", includeExpired,
                            DigestUtils.sha256Hex(accessTokenIdentifier)));
                } else {
                    log.debug("Retrieved access token from cache to verify.");
                }
            }
            // expiry time verification.
            boolean isTokenActive = true;
            if (!TokenMgtUtil.isActive(claimsSet.getExpirationTime())) {
                if (!includeExpired) {
                    throw new IdentityOAuth2Exception("Invalid Access Token. ACTIVE access token is not found.");
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
                    if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                        log.debug(String.format("Retrieved access token(hashed): %s from OAuthCache to verify.",
                                DigestUtils.sha256Hex(validationDataDO.getAccessToken())));
                    } else {
                        log.debug("Retrieved access token from cache to verify.");
                    }
                }
            } else {
                // create new AccessTokenDO with validated token information.
                validationDataDO = new AccessTokenDO();
                validationDataDO.setAccessToken(accessTokenIdentifier);
                validationDataDO.setConsumerKey(consumerKey);
                validationDataDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
                validationDataDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                        - claimsSet.getIssueTime().getTime());
                Object scopes = claimsSet.getClaim(PersistenceConstants.JWTClaim.SCOPE);
                validationDataDO.setScope(TokenMgtUtil.getScopes(scopes));
                AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
                validationDataDO.setAuthzUser(authenticatedUser);
                if (isTokenActive) {
                    validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
                } else {
                    validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
                }
                // TODO:// Read is_consented claim and set attribute
                // Add the token back to the cache in the case of a cache miss.
                TokenMgtUtil.addTokenToCache(accessTokenIdentifier, validationDataDO);
            }
        }
        return validationDataDO;
    }

    @Override
    public RefreshTokenValidationDataDO getVerifiedRefreshToken(String token, String consumerKey)
            throws IdentityOAuth2Exception {

        RefreshTokenValidationDataDO validationDataDO = null;
        if (!OAuth2Util.isJWT(token)) {
            log.debug("Refresh token is not a JWT. Hence, validating as an migrated opaque token from database.");
            // For backward compatibility, we check whether it is available in idn_oauth2_token table.
            validationDataDO = OpaqueTokenUtil.validateOpaqueRefreshToken(token, consumerKey);
            OpaqueTokenUtil.validateTokenConsent(validationDataDO);
            return validationDataDO;
        }
        SignedJWT signedJWT = TokenMgtUtil.parseJWT(token);
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        if (TokenMgtUtil.isRefreshTokenType(claimsSet)) {
            TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet);
            String consumerKeyFromToken = (String) claimsSet
                    .getClaim(PersistenceConstants.JWTClaim.AUTHORIZATION_PARTY);
            // validate consumer key in the request against the token.
            if (!StringUtils.equals(consumerKey, consumerKeyFromToken)) {
                throw new IdentityOAuth2Exception("Invalid refresh token. Consumer key does not match.");
            }
            String refreshTokenIdentifier = TokenMgtUtil.getTokenIdentifier(claimsSet);
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                    log.debug(String.format("Validating JWT refresh token (hashed): %s",
                            DigestUtils.sha256Hex(refreshTokenIdentifier)));
                } else {
                    log.debug("Validating JWT refresh token.");
                }
            }
            validationDataDO = new RefreshTokenValidationDataDO();
            // set expiration state according to jwt claim in it. Not throwing error when token is expired.
            if (TokenMgtUtil.isActive(claimsSet.getExpirationTime())) {
                /*
                 * check whether the token is not already revoked through direct revocations and following indirect
                 * revocations.
                 * 1. check if consumer app was changed.
                 * 2. check if user was changed.
                 */
                if (TokenMgtUtil.isTokenRevokedDirectly(refreshTokenIdentifier, consumerKey) ||
                        TokenMgtUtil.isTokenRevokedIndirectly(claimsSet)) {
                    validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                } else {
                    validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
                }
            } else {
                validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
            }
            // set other fields from jwt claims.
            validationDataDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
            validationDataDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                    - claimsSet.getIssueTime().getTime());
            validationDataDO.setScope(TokenMgtUtil.getScopes(claimsSet.getClaim(PersistenceConstants.JWTClaim.SCOPE)));
            validationDataDO.setConsented((boolean) claimsSet.getClaim(PersistenceConstants.JWTClaim.IS_CONSENTED));
            AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
            validationDataDO.setAuthorizedUser(authenticatedUser);
        }
        return validationDataDO;
    }
}
