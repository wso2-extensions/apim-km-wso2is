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
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
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
import org.wso2.is.key.manager.tokenpersistence.internal.ServiceReferenceHolder;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

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
                    log.debug("Token is used before Not_Before_Time." + ", Not Before Time(ms) : " + notBeforeTimeMillis
                            + ", TimeStamp Skew : " + timeStampSkewMillis + ", Current Time : " + currentTimeInMillis
                            + ". Token Rejected and validation terminated.");
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

        String username = getUserNameFromJWTClaims(claimsSet);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        AuthenticatedUser authenticatedUser = OAuth2Util.createAuthenticatedUser(
                UserCoreUtil.removeDomainFromName(tenantAwareUsername),
                IdentityUtil.extractDomainFromName(tenantAwareUsername).toUpperCase(),
                MultitenantUtils.getTenantDomain(username),
                getIDPForTokenIssuer(claimsSet).getIdentityProviderName());
        authenticatedUser.setAuthenticatedSubjectIdentifier(claimsSet.getSubject());
        return authenticatedUser;
    }

    /**
     * Get username from the JWT claims.
     *
     * @param claimsSet JWT claims set
     * @return Username
     * @throws IdentityOAuth2Exception If an error occurs while getting the username from the JWT claims.
     */
    public static String getUserNameFromJWTClaims(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        String userName = claimsSet.getSubject();
        RealmService realmService = ServiceReferenceHolder.getInstance().getRealmService();
        try {
            int tenantId = realmService.getTenantManager().getTenantId(TokenMgtUtil.getTenantDomain());
            AbstractUserStoreManager userStoreManager
                    = (AbstractUserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            // if useUserIdForDefaultSubject is enabled, consider the user id as the subject identifier.
            // else consider the username as the subject identifier.
            ServiceProviderProperty[] spProperties = TokenMgtUtil.getServiceProvider(
                    (String) claimsSet.getClaim(PersistenceConstants.AUTHORIZATION_PARTY),
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
            throw new IdentityOAuth2Exception("Unable to locate certificate for Identity Provider: " + idp
                    .getDisplayName());
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
            throw new IdentityOAuth2Exception("Invalid token type received");
        }
    }

    /**
     * Check if token is in-directly revoked through a user related or client application related change action.
     *
     * @param authenticatedSubjectIdentifier Authenticated Subject Identifier
     * @param consumerKey                    Consumer Key
     * @param tokenIssuedTime                Token Issued Time
     * @return True if token is in-directly revoked
     * @throws IdentityOAuth2Exception If failed to check is token is in-directly revoked
     */
    public static boolean isTokenRevokedIndirectly(String authenticatedSubjectIdentifier, String consumerKey,
                                                   Date tokenIssuedTime) throws IdentityOAuth2Exception {

        //TODO:// check if revoked by user action and remove following return statement.
        return ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService()
                .isRevokedJWTConsumerKeyExist(consumerKey, tokenIssuedTime);
    }

    /**
     * Check if token is directly revoked by calling revoked token endpoint.
     *
     * @param tokenIdentifier Token Identifier
     * @param consumerKey     Consumer Key
     * @return True if token is directly revoked
     * @throws IdentityOAuth2Exception If failed to check is token is directly revoked
     */
    public static boolean isTokenRevokedDirectly(String tokenIdentifier, String consumerKey)
            throws IdentityOAuth2Exception {

        return ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService().isInvalidToken(
                TokenMgtUtil.getTokenIdentifier(tokenIdentifier, consumerKey), consumerKey);
    }

    /**
     * Check if provided JWT token is a refresh token or not.
     *
     * @param claimsSet JWTClaimsSet of the parsed token.
     * @return True if the token is a refresh token.
     * @throws IdentityOAuth2Exception If the token type is invalid.
     */
    public static boolean isRefreshTokenType(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        if (claimsSet.getClaim(PersistenceConstants.TOKEN_TYPE_ELEM) != null
                && PersistenceConstants.REFRESH_TOKEN.equals(
                claimsSet.getClaim(PersistenceConstants.TOKEN_TYPE_ELEM).toString())) {
            return true;
        }
        if (claimsSet.getClaim(PersistenceConstants.TOKEN_TYPE_ELEM) != null) {
            throw new IdentityOAuth2Exception("Invalid token type received");
        }
        return false;
    }

    /**
     * The default implementation resolves one certificate to Identity Provider and ignores the JWT header.
     * Override this method, to resolve and enforce the certificate in any other way
     * such as x5t attribute of the header.
     *
     * @param idp The identity provider, if you need it.
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

    public static boolean isActive(Date expirationTime) {
        long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        long expirationTimeInMillis = expirationTime.getTime();
        long currentTimeInMillis = System.currentTimeMillis();
        if ((currentTimeInMillis + timeStampSkewMillis) > expirationTimeInMillis) {
            if (log.isDebugEnabled()) {
                log.debug("Token is expired." +
                        ", Expiration Time(ms) : " + expirationTimeInMillis +
                        ", TimeStamp Skew : " + timeStampSkewMillis +
                        ", Current Time : " + currentTimeInMillis + ". Token Rejected and validation terminated.");
            }
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Expiration Time(exp) of Token was validated successfully.");
        }
        return true;
    }

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
}
