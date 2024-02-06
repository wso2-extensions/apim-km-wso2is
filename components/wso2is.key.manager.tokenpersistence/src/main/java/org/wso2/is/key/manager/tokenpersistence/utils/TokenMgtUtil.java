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

package org.wso2.is.key.manager.tokenpersistence.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.JWTUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.is.key.manager.tokenpersistence.PersistenceConstants;
import org.wso2.is.key.manager.tokenpersistence.internal.ServiceReferenceHolder;

import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.Optional;

/**
 * Util class for token management related activities.
 */
public class TokenMgtUtil {

    private static final Log log = LogFactory.getLog(TokenMgtUtil.class);

    /**
     * Get token identifier (JTI) for JWT.
     *
     * @param claimsSet Claim Set
     * @return JTI
     * @throws IdentityOAuth2Exception if JTI claim is not present in the JWTClaimSet of the access token.
     */
    public static String getTokenIdentifier(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        String jwtId = claimsSet.getJWTID();
        if (jwtId == null) {
            throw new IdentityOAuth2Exception("JTI could not be retrieved from the JWT token.");
        } else {
            return jwtId;
        }
    }

    /**
     * Parse JWT Token.
     *
     * @param accessToken Access Token
     * @return SignedJWT
     * @throws IdentityOAuth2Exception If an error occurs while parsing the JWT token
     */
    public static SignedJWT parseJWT(String accessToken) throws IdentityOAuth2Exception {

        try {
            return JWTUtils.parseJWT(accessToken);
        } catch (ParseException e) {
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug(String.format("Failed to parse the received token: %s", accessToken));
                } else {
                    log.debug("Failed to parse the received token.");
                }
            }
            throw new IdentityOAuth2Exception("Error while parsing token.", e);
        }
    }

    /**
     * Get JWT Claim sets for the given access token.
     *
     * @param signedJWT Signed JWT
     * @return JWT Claim sets
     * @throws IdentityOAuth2Exception If an error occurs while getting the JWT claim sets
     */
    public static JWTClaimsSet getTokenJWTClaims(SignedJWT signedJWT) throws IdentityOAuth2Exception {

        Optional<JWTClaimsSet> claimsSet = JWTUtils.getJWTClaimSet(signedJWT);
        if (!claimsSet.isPresent()) {
            throw new IdentityOAuth2Exception("Claim values are empty in the given Token.");
        }
        return claimsSet.get();
    }

    /**
     * Validate the JWT signature.
     *
     * @throws IdentityOAuth2Exception If signature verification fails or if an error occurs while
     *                                 validating the JWT signature.
     */
    public static void validateJWTSignature(SignedJWT signedJWT, JWTClaimsSet claimsSet)
            throws IdentityOAuth2Exception {

        try {
            X509Certificate x509Certificate;
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
            String tenantDomain = JWTUtils.getSigningTenantDomain(claimsSet, null);
            IdentityProvider idp = JWTUtils.getResidentIDPForIssuer(claimsSet, tenantDomain);
            // Get certificate from tenant if available in claims.
            Optional<X509Certificate> certificate = JWTUtils.getCertificateFromClaims(jwtClaimsSet);
            if (certificate.isPresent()) {
                x509Certificate = certificate.get();
            } else {
                x509Certificate = JWTUtils.resolveSignerCertificate(idp);
            }
            if (x509Certificate == null) {
                throw new IdentityOAuth2Exception("Unable to locate certificate for Identity Provider: "
                        + idp.getDisplayName());
            }
            String algorithm = JWTUtils.verifyAlgorithm(signedJWT);
            if (!JWTUtils.verifySignature(signedJWT, x509Certificate, algorithm)) {
                throw new IdentityOAuth2Exception(("Invalid signature."));
            }
        } catch (JOSEException | ParseException e) {
            throw new IdentityOAuth2Exception("Error while validating Token.", e);
        }
    }

    /**
     * Get Scope array from the scopes string object.
     *
     * @param scopes String object of scopes with delimiter space.
     * @return Array of scopes
     */
    public static String[] getScopes(Object scopes) {

        if (scopes instanceof String) {
            return ((String) scopes).split(" ");
        }
        return new String[0];
    }

    /**
     * Get authenticated user.
     *
     * @param claimsSet JWT claims set
     * @return AuthenticatedUser
     */
    public static AuthenticatedUser getAuthenticatedUser(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        AuthenticatedUser authenticatedUser;
        authenticatedUser = resolveAuthenticatedUserFromEntityId((String)
                claimsSet.getClaim(OAuth2Constants.ENTITY_ID));
        if (claimsSet.getClaim(OAuth2Constants.IS_FEDERATED) != null
                && (boolean) claimsSet.getClaim(OAuth2Constants.IS_FEDERATED)) {
            if (authenticatedUser == null) {
                authenticatedUser =
                        createFederatedAuthenticatedUser((String) claimsSet.getClaim(OAuth2Constants.ENTITY_ID));
            } else {
                authenticatedUser.setFederatedUser(true);
            }
        }
        if (authenticatedUser == null) {
            throw new IdentityOAuth2Exception("Error while getting authenticated user. Authenticated user not found.");
        }
        authenticatedUser.setAuthenticatedSubjectIdentifier(claimsSet.getSubject());
        return authenticatedUser;
    }

    /**
     * Get authenticated user from the entity ID.
     *
     * @param entityId Entity ID JWT Claim value which uniquely identifies the subject principle of the JWT. Eg: user
     * @return Username
     * @throws IdentityOAuth2Exception If an error occurs while getting the authenticated user
     */
    private static AuthenticatedUser resolveAuthenticatedUserFromEntityId(String entityId)
            throws IdentityOAuth2Exception {

        AuthenticatedUser authenticatedUser = null;
        // Assume entity Id is client Id
        Optional<OAuthAppDO> consumerApp = getOAuthApp(entityId);
        if (consumerApp.isPresent()) {
            authenticatedUser = consumerApp.get().getAppOwner();
        } else {
            // Assume entity ID is userId
            RealmService realmService = ServiceReferenceHolder.getInstance().getRealmService();
            try {
                int tenantId = realmService.getTenantManager().getTenantId(TokenMgtUtil.getTenantDomain());
                AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) realmService
                        .getTenantUserRealm(tenantId).getUserStoreManager();
                String userName = userStoreManager.getUserNameFromUserID(entityId);
                if (StringUtils.isNotBlank(userName)) {
                    authenticatedUser = OAuth2Util.getUserFromUserName(userName);
                    authenticatedUser.setUserId(entityId);
                }
            } catch (UserStoreException e) {
                throw new IdentityOAuth2Exception("Error while getting username from JWT.", e);
            }
        }
        return authenticatedUser;
    }

    /**
     * Get tenant domain from thread local carbon context.
     *
     * @return Tenant domain
     */
    public static String getTenantDomain() {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }

    /**
     * Check if token is in-directly revoked through a user related or client application related change action.
     *
     * @param claimsSet         JWTClaimsSet of the parsed token.
     * @param authenticatedUser Authenticated User
     * @return True if token is in-directly revoked.
     * @throws IdentityOAuth2Exception If failed to check is token is in-directly revoked.
     */
    public static boolean isTokenRevokedIndirectly(JWTClaimsSet claimsSet, AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        Date tokenIssuedTime = claimsSet.getIssueTime();
        String entityId = (String) claimsSet.getClaim(OAuth2Constants.ENTITY_ID);
        String consumerKey = (String) claimsSet.getClaim(PersistenceConstants.JWTClaim.AUTHORIZATION_PARTY);
        boolean isRevoked = isTokenRevokedIndirectlyFromApp(consumerKey, tokenIssuedTime);
        if (!isRevoked) {
            isRevoked = ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService()
                    .isTokenRevokedForSubjectEntity(entityId, tokenIssuedTime);
        }
        if (isRevoked) {
            String tenantDomain = null;
            if (authenticatedUser != null) {
                String[] scopes = TokenMgtUtil.getScopes(claimsSet.getClaim(PersistenceConstants.JWTClaim.SCOPE));
                // if revoked, remove the token information from oauth cache.
                OAuthUtil.clearOAuthCache(consumerKey, authenticatedUser,
                        OAuth2Util.buildScopeString(scopes), OAuthConstants.TokenBindings.NONE);
                OAuthUtil.clearOAuthCache(consumerKey, authenticatedUser,
                        OAuth2Util.buildScopeString(scopes));
                OAuthUtil.clearOAuthCache(consumerKey, authenticatedUser);
                tenantDomain = authenticatedUser.getTenantDomain();
            }
            String accessTokenIdentifier = TokenMgtUtil.getTokenIdentifier(claimsSet);
            OAuthCacheKey cacheKey = new OAuthCacheKey(accessTokenIdentifier);
            OAuthCache.getInstance().clearCacheEntry(cacheKey, tenantDomain);
        }
        return isRevoked;
    }

    /**
     * Check if a token is in-directly revoked through a client application related change action. This is used to
     * validate if a token is revoked through a client application related change action based on its issued time
     *
     * @param consumerKey     Consumer Key
     * @param tokenIssuedTime Token Issued Time
     * @return True if token is in-directly revoked.
     * @throws IdentityOAuth2Exception If failed to check is token is in-directly revoked.
     */
    public static boolean isTokenRevokedIndirectlyFromApp(String consumerKey, Date tokenIssuedTime)
            throws IdentityOAuth2Exception {

        return ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService()
                .isTokenRevokedForConsumerKey(consumerKey, tokenIssuedTime);
    }

    /**
     * Check if token is directly revoked by calling revoked token endpoint. This seamlessly validates current
     * tokens and not migrated tokens.
     *
     * @param tokenIdentifier Token Identifier
     * @param consumerKey     Consumer Key
     * @return True if token is directly revoked
     * @throws IdentityOAuth2Exception If failed to check is token is directly revoked
     */
    public static boolean isTokenRevokedDirectly(String tokenIdentifier, String consumerKey)
            throws IdentityOAuth2Exception {

        /*
         * Clearing of cache is already handled when direct revocation happens through oauth2 revocation service.
         * Hence, no need of clearing cache.
         */
        return ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService()
                .isInvalidToken(tokenIdentifier, consumerKey);
    }

    /**
     * Get AccessTokenDO from cache.
     *
     * @param accessTokenIdentifier Identifier
     * @return Optional AccessTokenDO
     */
    public static Optional<AccessTokenDO> getTokenDOFromCache(String accessTokenIdentifier) {

        AccessTokenDO accessTokenDO = null;
        if (OAuthCache.getInstance().isEnabled()) {
            CacheEntry result = OAuthCache.getInstance().getValueFromCache(getOAuthCacheKey(accessTokenIdentifier));
            // cache hit, do the type check.
            if (result instanceof AccessTokenDO) {
                accessTokenDO = (AccessTokenDO) result;
                if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(
                        IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug(String.format("Hit OAuthCache for accessTokenIdentifier: %s", accessTokenIdentifier));
                } else {
                    log.debug("Hit OAuthCache with accessTokenIdentifier");
                }
            }
        }
        return Optional.ofNullable(accessTokenDO);
    }

    /**
     * Adds an access token and its associated information to the OAuth cache for efficient retrieval.
     *
     * @param accessTokenIdentifier The identifier of the access token to be cached.
     * @param accessTokenDO         The AccessTokenDO (Access Token Data Object) containing information about the
     *                              access token.
     */
    public static void addTokenToCache(String accessTokenIdentifier, AccessTokenDO accessTokenDO) {

        if (OAuthCache.getInstance().isEnabled()) {
            OAuthCache.getInstance().addToCache(
                    TokenMgtUtil.getOAuthCacheKey(accessTokenIdentifier), accessTokenDO);
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug(String.format("Access token(hashed): %s added to OAuthCache.",
                            DigestUtils.sha256Hex(accessTokenIdentifier)));
                } else {
                    log.debug("Access token added to OAuthCache.");
                }
            }
        }
    }

    /**
     * Get OAuth cache key for access token identifier.
     *
     * @param accessTokenIdentifier Access token ID
     * @return OAuth Cache Key
     */
    public static OAuthCacheKey getOAuthCacheKey(String accessTokenIdentifier) {

        return new OAuthCacheKey(accessTokenIdentifier);
    }

    /**
     * Check if provided JWT token is a refresh token or not.
     *
     * @param claimsSet JWTClaimsSet of the parsed token.
     * @return True if the token is a refresh token.
     * @throws IdentityOAuth2Exception If the token type is invalid.
     */
    public static boolean isRefreshTokenType(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        if (claimsSet.getClaim(PersistenceConstants.JWTClaim.TOKEN_TYPE_ELEM) != null
                && PersistenceConstants.REFRESH_TOKEN.equals(
                claimsSet.getClaim(PersistenceConstants.JWTClaim.TOKEN_TYPE_ELEM).toString())) {
            return true;
        }
        if (claimsSet.getClaim(PersistenceConstants.JWTClaim.TOKEN_TYPE_ELEM) != null) {
            throw new IdentityOAuth2Exception("Invalid token type received");
        }
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug(String.format("The refresh_token claim missing in the JWT: %s. Hence not considering as a "
                        + "valid refresh token.", DigestUtils.sha256Hex(getTokenIdentifier(claimsSet))));
            } else {
                log.debug("The refresh_token claim missing in the JWT. Hence not considering as a " +
                        "valid refresh token.");
            }
        }
        return false;
    }

    /**
     * Get the OAuthAppDO for the provided client id. Assumes that client id is unique across tenants.
     *
     * @param clientId Client Id
     * @return OAuthAppDO for the provided client id. Null if the client id is not found.
     * @throws IdentityOAuth2Exception Error while retrieving the OAuthAppDO.
     */
    public static Optional<OAuthAppDO> getOAuthApp(String clientId) throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO = null;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
            if (log.isDebugEnabled()) {
                log.debug("Retrieved OAuth application : " + clientId + ". Authorized user : "
                        + oAuthAppDO.getAppOwner().toString());
            }
        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("OAuth application : " + clientId + " not found");
            }
        }
        return Optional.ofNullable(oAuthAppDO);
    }

    /**
     * Create an authenticated user object for the given user ID from usersession store.
     *
     * @param userId User ID
     * @return AuthenticatedUser
     */
    public static AuthenticatedUser createFederatedAuthenticatedUser(String userId) throws IdentityOAuth2Exception {

        AuthenticatedUser authenticatedUser;
        try {
            authenticatedUser = UserSessionStore.getInstance().getUser(userId);
            if (authenticatedUser == null) {
                throw new IdentityOAuth2Exception("Error occurred while resolving the user from the userId for the "
                        + "federated user. No user found for the userId");
            }
            authenticatedUser.setUserId(userId);
            authenticatedUser.setUserName(authenticatedUser.getUserName());
            authenticatedUser.setTenantDomain(authenticatedUser.getTenantDomain());
            authenticatedUser.setUserStoreDomain(authenticatedUser.getUserStoreDomain());
            authenticatedUser.setFederatedUser(true);
            authenticatedUser.setFederatedIdPName(authenticatedUser.getFederatedIdPName());
        } catch (UserSessionException e) {
            // In here we better not log the user id.
            throw new IdentityOAuth2Exception("Error occurred while resolving the user from the userId for the "
                    + "federated user", e);
        }
        return authenticatedUser;
    }

    /**
     * Get token id from the JWT token. This tokenId is the unique identifier of the logged-in session.
     *
     * @param claimsSet JWTClaimsSet of the parsed token.
     * @return Token Id
     * @throws IdentityOAuth2Exception If failed to get the token id.
     */
    public static String getTokenId(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        String tokenId = claimsSet.getClaim(OAuth2Constants.USER_SESSION_ID) != null ?
                claimsSet.getClaim(OAuth2Constants.USER_SESSION_ID).toString() : null;
        if (tokenId == null) {
            throw new IdentityOAuth2Exception("TokenId could not be retrieved from the JWT token.");
        } else {
            return tokenId;
        }
    }
}
