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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.is.key.manager.tokenpersistence.PersistenceConstants;
import org.wso2.is.key.manager.tokenpersistence.dao.ExtendedAccessTokenDAOImpl;
import org.wso2.is.key.manager.tokenpersistence.internal.ServiceReferenceHolder;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Util class for token management related activities.
 */
public class TokenMgtUtil {

    private static final Log log = LogFactory.getLog(TokenMgtUtil.class);
    private static final String OIDC_IDP_ENTITY_ID = "IdPEntityId";
    private static final String ALGO_PREFIX = "RS";
    private static final String ALGO_PREFIX_PS = "PS";

    /**
     * Get the JTI of the JWT token passed using the OAuthTokenIssuer of the given consumer app.
     *
     * @param token       Token
     * @param consumerKey Consumer key
     * @return JTI of the JWT token
     * @throws IdentityOAuth2Exception If an error occurs while getting the JTI
     */
    public static String getTokenIdentifier(String token, String consumerKey)
            throws IdentityOAuth2Exception {

        String accessTokenHash = token;
        try {
            OauthTokenIssuer oauthTokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(consumerKey);
            //check for persist alias for the token type
            if (oauthTokenIssuer.usePersistedAccessTokenAlias()) {
                accessTokenHash = oauthTokenIssuer.getAccessTokenHash(token);
            }
            return accessTokenHash;
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Error while getting access token hash for token(hashed): " + DigestUtils
                        .sha256Hex(accessTokenHash));
            }
            throw new IdentityOAuth2Exception("Error while getting access token hash.", e);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception(
                    "Error while retrieving oauth issuer for the app with clientId: " + consumerKey, e);
        }
    }

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
            return SignedJWT.parse(accessToken);
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

        try {
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet == null) {
                throw new IdentityOAuth2Exception("Claim values are empty in the given Token.");
            }
            return claimsSet;
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error while retrieving claim set from Token.", e);
        }
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
            if (!TokenMgtUtil.isValidSignature(signedJWT, getIDPForTokenIssuer(claimsSet))) {
                throw new IdentityOAuth2Exception(("Invalid signature."));
            }
        } catch (JOSEException | ParseException e) {
            throw new IdentityOAuth2Exception("Error while validating signature.", e);
        }
    }

    /**
     * Get Identity provider for the given issuer.
     *
     * @param claimsSet JWT claim set
     * @return Identity provider
     * @throws IdentityOAuth2Exception If an error occurs while getting the identity provider
     */
    public static IdentityProvider getIDPForTokenIssuer(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        return TokenMgtUtil.getResidentIDPForIssuer(claimsSet.getIssuer());
    }

    /**
     * Validate not before time of the JWT token.
     *
     * @param notBeforeTime Not before time
     * @throws IdentityOAuth2Exception If the token is used before the not before time.
     */
    public static void checkNotBeforeTime(Date notBeforeTime) throws IdentityOAuth2Exception {

        if (notBeforeTime != null) {
            long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
            long notBeforeTimeMillis = notBeforeTime.getTime();
            long currentTimeInMillis = System.currentTimeMillis();
            if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Token is used before Not_Before_Time. Not Before Time(ms) : %s, TimeStamp "
                                    + "Skew : %s, Current Time : %s. Token Rejected and validation terminated.",
                            notBeforeTimeMillis, timeStampSkewMillis, currentTimeInMillis));
                }
                throw new IdentityOAuth2Exception("Token is used before Not_Before_Time.");
            }
            log.debug("Not Before Time(nbf) of Token was validated successfully.");
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
        if (claimsSet.getClaim(OAuth2Constants.ENTITY_ID) != null) {
            authenticatedUser = resolveAuthenticatedUserFromEntityId((String)
                    claimsSet.getClaim(OAuth2Constants.ENTITY_ID));
        } else {
            String username = getUserNameFromSubject(claimsSet);
            if (username == null) {
                authenticatedUser = new AuthenticatedUser();
                authenticatedUser.setUserName(claimsSet.getSubject());
            } else {
                String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
                authenticatedUser = OAuth2Util.createAuthenticatedUser(
                        UserCoreUtil.removeDomainFromName(tenantAwareUsername),
                        IdentityUtil.extractDomainFromName(tenantAwareUsername).toUpperCase(),
                        MultitenantUtils.getTenantDomain(username),
                        getIDPForTokenIssuer(claimsSet).getIdentityProviderName());
            }
        }
        if (authenticatedUser != null) {
            authenticatedUser.setAuthenticatedSubjectIdentifier(claimsSet.getSubject());
        }
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
                }
            } catch (UserStoreException e) {
                throw new IdentityOAuth2Exception("Error while getting username from JWT.", e);
            }
        }

        return authenticatedUser;
    }

    /**
     * Get username from the JWT claims.
     *
     * @param claimsSet JWT claims set
     * @return Username
     * @throws IdentityOAuth2Exception If an error occurs while getting the username from the JWT claims.
     */
    private static String getUserNameFromSubject(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        String userName = claimsSet.getSubject();
        RealmService realmService = ServiceReferenceHolder.getInstance().getRealmService();
        try {
            int tenantId = realmService.getTenantManager().getTenantId(TokenMgtUtil.getTenantDomain());
            AbstractUserStoreManager userStoreManager
                    = (AbstractUserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            // if useUserIdForDefaultSubject is enabled, consider the user id as the subject identifier.
            // else consider the username as the subject identifier.
            ServiceProviderProperty[] spProperties = TokenMgtUtil.getServiceProvider(
                    (String) claimsSet.getClaim(PersistenceConstants.JWTClaim.AUTHORIZATION_PARTY),
                    TokenMgtUtil.getTenantDomain()).getSpProperties();
            boolean useUserIdForDefaultSubject = false;
            if (spProperties != null) {
                for (ServiceProviderProperty prop : spProperties) {
                    if (IdentityApplicationConstants.USE_USER_ID_FOR_DEFAULT_SUBJECT.equals(prop.getName())) {
                        useUserIdForDefaultSubject = Boolean.parseBoolean(prop.getValue());
                        break;
                    }
                }
            }
            if (useUserIdForDefaultSubject) {
                userName = userStoreManager.getUserNameFromUserID(claimsSet.getSubject());
            }
        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception("Error while getting username from JWT.", e);
        }
        return userName;
    }

    /**
     * Get Resident Identity Provider for the given issuer in JWT.
     *
     * @param jwtIssuer JWT Issuer
     * @return IdentityProvider
     * @throws IdentityOAuth2Exception If an error occurs while getting the Resident Identity Provider.
     */
    public static IdentityProvider getResidentIDPForIssuer(String jwtIssuer) throws IdentityOAuth2Exception {

        String tenantDomain = getTenantDomain();
        String issuer = StringUtils.EMPTY;
        IdentityProvider residentIdentityProvider;
        try {
            residentIdentityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg =
                    String.format("Error while getting Resident Identity Provider of '%s' tenant.", tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
        FederatedAuthenticatorConfig[] fedAuthnConfigs = residentIdentityProvider.getFederatedAuthenticatorConfigs();
        FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        if (oauthAuthenticatorConfig != null) {
            issuer = IdentityApplicationManagementUtil.getProperty(oauthAuthenticatorConfig.getProperties(),
                    OIDC_IDP_ENTITY_ID).getValue();
        }
        if (!jwtIssuer.equals(issuer)) {
            throw new IdentityOAuth2Exception("No Registered IDP found for the token with issuer name : " + jwtIssuer);
        }
        return residentIdentityProvider;
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
     * Validate the signature of the JWT token.
     *
     * @param signedJWT Signed JWT token
     * @param idp       Identity provider
     * @return true if signature is valid.
     * @throws JOSEException           If an error occurs while validating the signature.
     * @throws IdentityOAuth2Exception If an error occurs while getting the tenant domain.
     * @throws ParseException          If an error occurs while parsing the JWT token.
     */
    public static boolean isValidSignature(SignedJWT signedJWT, IdentityProvider idp) throws JOSEException,
            IdentityOAuth2Exception, ParseException {

        JWSVerifier verifier = null;
        X509Certificate x509Certificate = null;
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        Map realm = (HashMap) jwtClaimsSet.getClaim(OAuthConstants.OIDCClaims.REALM);
        // Get certificate from tenant if available in claims.
        if (MapUtils.isNotEmpty(realm)) {
            String tenantDomain = null;
            // Get signed key tenant from JWT token or ID token based on claim key.
            if (realm.get(OAuthConstants.OIDCClaims.SIGNING_TENANT) != null) {
                tenantDomain = (String) realm.get(OAuthConstants.OIDCClaims.SIGNING_TENANT);
            } else if (realm.get(OAuthConstants.OIDCClaims.TENANT) != null) {
                tenantDomain = (String) realm.get(OAuthConstants.OIDCClaims.TENANT);
            }
            if (tenantDomain != null) {
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                x509Certificate = (X509Certificate) OAuth2Util.getCertificate(tenantDomain, tenantId);
            }
        } else {
            x509Certificate = resolveSignerCertificate(idp);
        }
        if (x509Certificate == null) {
            throw new IdentityOAuth2Exception("Unable to locate certificate for Identity Provider: "
                    + idp.getDisplayName());
        }
        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (StringUtils.isEmpty(alg)) {
            throw new IdentityOAuth2Exception("Algorithm must not be null.");
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm found in the Token Header: " + alg);
            }
            if (alg.indexOf(ALGO_PREFIX) == 0 || alg.indexOf(ALGO_PREFIX_PS) == 0) {
                // At this point 'x509Certificate' will never be null.
                PublicKey publicKey = x509Certificate.getPublicKey();
                if (publicKey instanceof RSAPublicKey) {
                    verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                } else {
                    throw new IdentityOAuth2Exception("Public key is not an RSA public key.");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Signature Algorithm not supported yet: " + alg);
                }
            }
            if (verifier == null) {
                throw new IdentityOAuth2Exception("Could not create a signature verifier for algorithm type: " + alg);
            }
        }
        boolean isValid = signedJWT.verify(verifier);
        if (log.isDebugEnabled()) {
            log.debug("Signature verified: " + isValid);
        }
        return isValid;
    }

    /**
     * Check if the token is a JWT token.
     *
     * @param token The token to be checked.
     * @throws IdentityOAuth2Exception If the token is not a JWT token.
     */
    public static void isJWTToken(String token) throws IdentityOAuth2Exception {

        if (!OAuth2Util.isJWT(token)) {
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug(String.format("Token is not a JWT: %s", DigestUtils.sha256Hex(token)));
                } else {
                    log.debug("Token is not a JWT");
                }
            }
            throw new IdentityOAuth2Exception("Invalid token type received");
        }
        log.debug("Token is a valid JWT.");
    }

    /**
     * Check if token is in-directly revoked through a user related or client application related change action.
     *
     * @return True if token is in-directly revoked.
     * @throws IdentityOAuth2Exception If failed to check is token is in-directly revoked.
     */
    public static boolean isTokenRevokedIndirectly(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        Date tokenIssuedTime = claimsSet.getIssueTime();
        String entityId = (String) claimsSet.getClaim(OAuth2Constants.ENTITY_ID);
        String consumerKey = (String) claimsSet.getClaim(PersistenceConstants.JWTClaim.AUTHORIZATION_PARTY);
        boolean isRevoked = ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService()
                .isTokenRevokedForConsumerKey(consumerKey, tokenIssuedTime);
        if (!isRevoked) {
            isRevoked = ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService()
                    .isTokenRevokedForSubjectEntity(entityId, tokenIssuedTime);
        }
        if (isRevoked) {
            AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
            String[] scopes = TokenMgtUtil.getScopes(claimsSet.getClaim(PersistenceConstants.JWTClaim.SCOPE));
            String accessTokenIdentifier = TokenMgtUtil.getTokenIdentifier(claimsSet);
            // if revoked, remove the token information from oauth cache.
            if (authenticatedUser != null) {
                OAuthUtil.clearOAuthCache(consumerKey, authenticatedUser,
                        OAuth2Util.buildScopeString(scopes), OAuthConstants.TokenBindings.NONE);
                OAuthUtil.clearOAuthCache(consumerKey, authenticatedUser,
                        OAuth2Util.buildScopeString(scopes));
                OAuthUtil.clearOAuthCache(consumerKey, authenticatedUser);
                OAuthCacheKey cacheKey = new OAuthCacheKey(accessTokenIdentifier);
                String tenantDomain = authenticatedUser.getTenantDomain();
                OAuthCache.getInstance().clearCacheEntry(cacheKey, tenantDomain);
            }
        }
        return isRevoked;
    }

    /**
     * Check if token is directly revoked by calling revoked token endpoint. This seamlessly validates both current
     * tokens and migrated tokens.
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
        boolean isInvalid = ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService()
                .isInvalidToken(tokenIdentifier, consumerKey);
        if (!isInvalid) {
            /*
             * Token can be a migrated one from a previous product version. Hence, validating it against old token
             * table.
             */
            AccessTokenDAO accessTokenDAO = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO();
            if (accessTokenDAO instanceof ExtendedAccessTokenDAOImpl) {
                isInvalid = ((ExtendedAccessTokenDAOImpl) accessTokenDAO).isInvalidToken(tokenIdentifier);
            } else {
                throw new IdentityOAuth2Exception("Failed to check if the token is directly revoked. Unsupported DAO "
                        + "Implementation.");
            }
        }
        return isInvalid;
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
     * @param accessTokenIdentifier Access token Id
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
     * The default implementation resolves one certificate to Identity Provider.
     *
     * @param idp The identity provider
     * @return the resolved X509 Certificate, to be used to validate the JWT signature.
     * @throws IdentityOAuth2Exception something goes wrong.
     */
    private static X509Certificate resolveSignerCertificate(IdentityProvider idp) throws IdentityOAuth2Exception {

        X509Certificate x509Certificate;
        String tenantDomain = getTenantDomain();
        try {
            x509Certificate = (X509Certificate) IdentityApplicationManagementUtil
                    .decodeCertificate(idp.getCertificate());
        } catch (CertificateException e) {
            throw new IdentityOAuth2Exception("Error occurred while decoding public certificate of Identity Provider "
                    + idp.getIdentityProviderName() + " for tenant domain " + tenantDomain, e);
        }
        return x509Certificate;
    }

    /**
     * Checks if a token is active based on its expiration time and a timestamp skew.
     *
     * @param expirationTime The expiration time of the token to be checked.
     * @return {@code true} if the token is active (not expired), {@code false} if the token is expired.
     */
    public static boolean isActive(Date expirationTime) {

        // Calculate the timestamp skew in milliseconds.
        long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        // Convert the expiration time, current time, and calculate the threshold time.
        long expirationTimeInMillis = expirationTime.getTime();
        long currentTimeInMillis = System.currentTimeMillis();
        // Check if the current time is greater than the threshold time.
        if ((currentTimeInMillis + timeStampSkewMillis) > expirationTimeInMillis) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Token is expired. Expiration Time(ms) : %s, TimeStamp Skew : %s, "
                                + "Current Time : %s. Token Rejected and validation terminated.",
                        expirationTimeInMillis, timeStampSkewMillis, currentTimeInMillis));
            }
            return false; // Token is expired
        }
        // Token is not expired
        log.debug("Expiration Time(exp) of Token was validated successfully.");
        return true;
    }

    /**
     * Get the service provider for the given client id.
     *
     * @param clientId     Client Id
     * @param tenantDomain Tenant Domain
     * @return Service Provider
     * @throws IdentityOAuth2Exception If an error occurred while retrieving the service provider.
     */
    public static ServiceProvider getServiceProvider(String clientId, String tenantDomain)
            throws IdentityOAuth2Exception {

        ServiceProvider serviceProvider;
        try {
            serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().getServiceProviderByClientId(
                    clientId, OAuthConstants.Scope.OAUTH2, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for client id "
                    + clientId, e);
        }
        if (serviceProvider == null) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find an application for client id: " + clientId
                        + ", scope: " + OAuthConstants.Scope.OAUTH2 + ", tenant: " + tenantDomain);
            }
            throw new IdentityOAuth2Exception("Service Provider not found");
        }
        if (log.isDebugEnabled()) {
            log.debug("Retrieved service provider: " + serviceProvider.getApplicationName() + " for client: " +
                    clientId + ", scope: " + OAuthConstants.Scope.OAUTH2 + ", tenant: " +
                    tenantDomain);
        }
        return serviceProvider;
    }

    /**
     * Get the OAuthAppDO for the provided client id.
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
            if (!e.getMessage()
                    .contains(OAuthConstants.OAuthError.AuthorizationResponsei18nKey.APPLICATION_NOT_FOUND)) {
                throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: "
                        + clientId, e);
            }
        }
        return Optional.ofNullable(oAuthAppDO);
    }
}
