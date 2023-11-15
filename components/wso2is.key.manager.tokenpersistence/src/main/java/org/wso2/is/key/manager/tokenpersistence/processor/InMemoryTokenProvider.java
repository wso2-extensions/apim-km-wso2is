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
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.JWTUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.is.key.manager.tokenpersistence.PersistenceConstants;
import org.wso2.is.key.manager.tokenpersistence.internal.ServiceReferenceHolder;
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

    /**
     * Retrieves and verifies JWT access token based on the JWT claims with an option to include expired tokens
     * as valid in the verification process.
     *
     * @param token          The access token JWT to retrieve and verify.
     * @param includeExpired A boolean flag indicating whether to include expired tokens in the verification.
     *                       Set to true to include expired tokens, false to exclude them.
     * @return The AccessTokenDO if the token is valid (ACTIVE or, optionally, EXPIRED), or null if the token
     * is not found either in ACTIVE or EXPIRED states when includeExpired is true. The method should throw
     * IllegalArgumentException if the access token is in an inactive or invalid state (e.g., 'REVOKED')
     * when includeExpired is false.
     * @throws IdentityOAuth2Exception If there is an error during the access token retrieval or verification process.
     */
    @Override
    public AccessTokenDO getVerifiedAccessToken(String token, boolean includeExpired) throws IdentityOAuth2Exception {

        // check if token is JWT.
        if (!JWTUtils.isJWT(token)) {
            // assume this is a migrated access token, validate and get the token from the database in the old way.
            return getMigratedAccessToken(token, includeExpired);
        }
        SignedJWT signedJWT = TokenMgtUtil.parseJWT(token);
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        // get JTI of the token.
        String accessTokenIdentifier = TokenMgtUtil.getTokenIdentifier(claimsSet);
        /*
         * No need to validate the consumer key in the token with the consumer key in the verification request, as
         * it is done by the calling functions. eg: OAuth2Service.revokeTokenByOAuthClient().
         */
        String consumerKey = (String) claimsSet.getClaim(PersistenceConstants.JWTClaim.AUTHORIZATION_PARTY);
        if (claimsSet.getClaim(OAuth2Constants.ENTITY_ID) == null) {
            return getMigratedAccessToken(accessTokenIdentifier, includeExpired);
        }
        AccessTokenDO validationDataDO = null;
        // check if token_type is refresh_token, if yes, throw no active token error.
        if (!TokenMgtUtil.isRefreshTokenType(claimsSet)) {
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug(String.format("Validating JWT access token: %s with expiry: %s", includeExpired,
                            DigestUtils.sha256Hex(accessTokenIdentifier)));
                } else {
                    log.debug(String.format("Validating JWT access token with expiry: %s", includeExpired));
                }
            }
            // validate JWT token signature.
            TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet);
            // expiry time verification.
            boolean isTokenActive = true;
            if (!JWTUtils.checkExpirationTime(claimsSet.getExpirationTime())) {
                if (!includeExpired) {
                    // this means the token is not active, so we can't proceed further.
                    handleInvalidAccessTokenError(accessTokenIdentifier);
                }
                isTokenActive = false;
            }
            // not before time verification.
            JWTUtils.checkNotBeforeTime(claimsSet.getNotBeforeTime());
            AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
            /*
             * check whether the token is already revoked through direct revocations and through following indirect
             * revocation events.
             * 1. check if consumer app was changed.
             * 2. check if user was changed.
             */
            if (TokenMgtUtil.isTokenRevokedDirectly(accessTokenIdentifier, consumerKey)
                    || TokenMgtUtil.isTokenRevokedIndirectly(claimsSet, authenticatedUser)) {
                if (!includeExpired) {
                    handleInvalidAccessTokenError(accessTokenIdentifier);
                }
                return null; // even if the token is invalid/revoked, we return null if includeExpired is true.
            }
            Optional<AccessTokenDO> accessTokenDO = TokenMgtUtil.getTokenDOFromCache(accessTokenIdentifier);
            if (accessTokenDO.isPresent()) {
                validationDataDO = accessTokenDO.get();
                TokenMgtUtil.cleanupAccessTokenDO(validationDataDO);
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
                validationDataDO.setAuthzUser(authenticatedUser);
                RealmService realmService = ServiceReferenceHolder.getInstance().getRealmService();
                try {
                    int tenantId = realmService.getTenantManager().getTenantId(authenticatedUser.getTenantDomain());
                    validationDataDO.setTenantID(tenantId);
                } catch (UserStoreException e) {
                    throw new IdentityOAuth2Exception("Error while getting tenant ID from tenant domain:"
                            + authenticatedUser.getTenantDomain(), e);
                }
                if (isTokenActive) {
                    validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
                } else {
                    validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
                }
                if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
                    // claim can only be null for migrated tokens, which are already handled above.Hence, no null check.
                    validationDataDO.setIsConsentedToken(
                            (boolean) claimsSet.getClaim(PersistenceConstants.JWTClaim.IS_CONSENTED));
                }
                // Add the token back to the cache in the case of a cache miss.
                TokenMgtUtil.addTokenToCache(accessTokenIdentifier, validationDataDO);
            }
        } else {
            // not a valid access token.
            if (!includeExpired) {
                handleInvalidAccessTokenError(accessTokenIdentifier);
            }
        }
        return validationDataDO;
    }

    /**
     * Retrieves and verifies a refresh token.
     *
     * @param refreshToken The refresh token to retrieve and verify
     * @param consumerKey  Consumer key
     * @return The RefreshTokenValidationDataDO if the token is valid (ACTIVE, EXPIRED or REVOKED), or null if the token
     * is not found in either states.
     * @throws IdentityOAuth2Exception If there is an error during the access token retrieval or verification process.
     */
    @Override
    public RefreshTokenValidationDataDO getVerifiedRefreshToken(String refreshToken, String consumerKey)
            throws IdentityOAuth2Exception {

        RefreshTokenValidationDataDO validationDataDO = null;
        if (!JWTUtils.isJWT(refreshToken)) {
            log.debug("Refresh token is not a JWT. Hence, validating as an migrated opaque token from database.");
            // For backward compatibility, we check whether it is available in idn_oauth2_token table.
            validationDataDO = OpaqueTokenUtil.validateOpaqueRefreshToken(refreshToken, consumerKey);
            // check whether the token is already revoked through direct revocations after migration.
            if (TokenMgtUtil.isTokenRevokedDirectly(refreshToken, consumerKey)
                    || TokenMgtUtil.isTokenRevokedIndirectlyFromApp(consumerKey, validationDataDO.getIssuedTime())) {
                validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
            }
            OpaqueTokenUtil.validateTokenConsent(validationDataDO);
            TokenMgtUtil.cleanupRefreshTokenDO(validationDataDO);
            return validationDataDO;
        }
        SignedJWT signedJWT = TokenMgtUtil.parseJWT(refreshToken);
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        String consumerKeyFromToken = (String) claimsSet
                .getClaim(PersistenceConstants.JWTClaim.AUTHORIZATION_PARTY);
        // validate consumer key in the request against the token.
        if (!StringUtils.equals(consumerKey, consumerKeyFromToken)) {
            throw new IdentityOAuth2Exception("Invalid refresh token. Consumer key does not match.");
        }
        // if token_type is not refresh_token, return null.
        if (TokenMgtUtil.isRefreshTokenType(claimsSet)) {
            validationDataDO = validateJWTRefreshToken(claimsSet, signedJWT);
        }
        return validationDataDO;
    }

    /**
     * Validates the refresh token to check whether it is active and returns the validation data in an AccessTokenDO.
     *
     * @param refreshToken The refresh token to validate
     * @return The AccessTokenDO if the token is valid (ACTIVE), or null if the token is not found in active state
     * @throws IdentityOAuth2Exception If there is an error during the refresh token validation process.
     */
    @Override
    public AccessTokenDO getVerifiedRefreshToken(String refreshToken) throws IdentityOAuth2Exception {

        AccessTokenDO accessTokenDO = null;
        if (!OAuth2Util.isJWT(refreshToken)) {
            log.debug("Refresh token is not a JWT. Hence, finding as an migrated opaque token from database.");
            // For backward compatibility, we check whether it is available in idn_oauth2_token table.
            accessTokenDO = OpaqueTokenUtil.findRefreshToken(refreshToken);
            if (accessTokenDO == null) {
                return null; // if no active refresh token found.
            }
            TokenMgtUtil.cleanupAccessTokenDO(accessTokenDO);
            accessTokenDO.setAccessToken(null);
            // check whether the token is already revoked through direct revocations after migration.
            if (TokenMgtUtil.isTokenRevokedDirectly(refreshToken, accessTokenDO.getConsumerKey())
                    || TokenMgtUtil.isTokenRevokedIndirectlyFromApp(accessTokenDO.getConsumerKey(),
                    accessTokenDO.getRefreshTokenIssuedTime())) {
                return null; // only return AccessTokenDO for active refresh tokens.
            }
            return accessTokenDO;
        }
        SignedJWT signedJWT = TokenMgtUtil.parseJWT(refreshToken);
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        // if token_type is not refresh_token, return null.
        if (TokenMgtUtil.isRefreshTokenType(claimsSet)) {
            RefreshTokenValidationDataDO validationDataDO = validateJWTRefreshToken(claimsSet, signedJWT);
            if (StringUtils.equals(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE,
                    validationDataDO.getRefreshTokenState())) {
                /*
                 * By this time, we do not have a particular access token generated for the given refresh token
                 * hence populating only the minimal information needed for the token validation.
                 */
                accessTokenDO = new AccessTokenDO();
                accessTokenDO.setRefreshTokenValidityPeriodInMillis(validationDataDO.getValidityPeriodInMillis());
                accessTokenDO.setRefreshTokenIssuedTime(validationDataDO.getIssuedTime());
                accessTokenDO.setScope(validationDataDO.getScope());
                accessTokenDO.setAuthzUser(validationDataDO.getAuthorizedUser());
                accessTokenDO.setConsumerKey((String) claimsSet
                        .getClaim(PersistenceConstants.JWTClaim.AUTHORIZATION_PARTY));
                RealmService realmService = ServiceReferenceHolder.getInstance().getRealmService();
                try {
                    int tenantId = realmService.getTenantManager().getTenantId(validationDataDO.getAuthorizedUser()
                            .getTenantDomain());
                    accessTokenDO.setTenantID(tenantId);
                } catch (UserStoreException e) {
                    throw new IdentityOAuth2Exception("Error while getting tenant ID from tenant domain:"
                            + validationDataDO.getAuthorizedUser().getTenantDomain(), e);
                }
            }
        }
        return accessTokenDO;
    }

    /**
     * Handles throwing of error when active or valid access token not found.
     *
     * @param tokenIdentifier Token Identifier (JTI) of the JWT
     */
    private void handleInvalidAccessTokenError(String tokenIdentifier) {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug(String.format("Failed to validate the JWT Access Token %s in memory.",
                        DigestUtils.sha256Hex(tokenIdentifier)));
            } else {
                log.debug("Failed to validate the JWT Access Token in memory.");
            }
        }
        throw new IllegalArgumentException(OAuth2Util.ACCESS_TOKEN_IS_NOT_ACTIVE_ERROR_MESSAGE);
    }

    /**
     * Validates the JWT refresh token.
     *
     * @param claimsSet JWT claim set
     * @param signedJWT Signed JWT
     * @return RefreshTokenValidationDataDO
     * @throws IdentityOAuth2Exception If an error occurred while validating the JWT refresh token.
     */
    private RefreshTokenValidationDataDO validateJWTRefreshToken(JWTClaimsSet claimsSet, SignedJWT signedJWT)
            throws IdentityOAuth2Exception {

        RefreshTokenValidationDataDO validationDataDO = new RefreshTokenValidationDataDO();
        String consumerKey = (String) claimsSet
                .getClaim(PersistenceConstants.JWTClaim.AUTHORIZATION_PARTY);
        String refreshTokenIdentifier = TokenMgtUtil.getTokenIdentifier(claimsSet);
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                log.debug(String.format("Validating JWT refresh token (hashed): %s",
                        DigestUtils.sha256Hex(refreshTokenIdentifier)));
            } else {
                log.debug("Validating JWT refresh token.");
            }
        }
        TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet);
        AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
        // set expiration state according to jwt claim in it. Not throwing error when token is expired.
        if (JWTUtils.checkExpirationTime(claimsSet.getExpirationTime())) {
            /*
             * check whether the token is not already revoked through direct revocations and following indirect
             * revocations.
             * 1. check if consumer app was changed.
             * 2. check if user was changed.
             */
            if (TokenMgtUtil.isTokenRevokedDirectly(refreshTokenIdentifier, consumerKey)
                    || TokenMgtUtil.isTokenRevokedIndirectly(claimsSet, authenticatedUser)) {
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
        if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled() &&
                claimsSet.getClaim(PersistenceConstants.JWTClaim.IS_CONSENTED) != null) {
            validationDataDO.setConsented(
                    (boolean) claimsSet.getClaim(PersistenceConstants.JWTClaim.IS_CONSENTED));
        }
        validationDataDO.setAuthorizedUser(authenticatedUser);
        return validationDataDO;
    }

    /**
     * Retrieves and verifies a migrated access token based on the provided access token data object. A migrated access
     * token can be either an Opaque or a JWT with entity_id : null.
     *
     * @param accessTokenIdentifier Access token identifier
     * @param includeExpired        A boolean flag indicating whether to include expired tokens in the verification.
     * @return AccessTokenDO if the token is valid (ACTIVE or, optionally, EXPIRED), or null if the token is not found
     * or revoked
     * @throws IdentityOAuth2Exception If there is an error during the access token retrieval or verification process.
     */
    private AccessTokenDO getMigratedAccessToken(String accessTokenIdentifier, boolean includeExpired)
            throws IdentityOAuth2Exception {

        AccessTokenDO accessTokenDO;
        // If token is migrated (entity_id : null), validate and get the token from the database in the old way.
        accessTokenDO = OAuth2Util.findAccessToken(accessTokenIdentifier, includeExpired);
        // If no access token found in active or expired state as requested.
        if (accessTokenDO == null) {
            return null;
        }
        TokenMgtUtil.cleanupAccessTokenDO(accessTokenDO);
        // check whether the token is already revoked through direct revocations.
        if (TokenMgtUtil.isTokenRevokedDirectly(accessTokenIdentifier, accessTokenDO.getConsumerKey())
                || TokenMgtUtil.isAccessTokenRevokedIndirectlyFromApp(accessTokenDO)) {
            if (!includeExpired) {
                handleInvalidAccessTokenError(accessTokenIdentifier);
            }
            return null; // even if the token is invalid/revoked, we return null if includeExpired is true.
        }
        return accessTokenDO;
    }
}
