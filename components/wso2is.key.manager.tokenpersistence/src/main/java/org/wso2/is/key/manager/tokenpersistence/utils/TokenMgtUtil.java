/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
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
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
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
 * 
 * Util class for token related actvities.
 *
 */
public class TokenMgtUtil {

    private static final Log log = LogFactory.getLog(TokenMgtUtil.class);
    private static final String OIDC_IDP_ENTITY_ID = "IdPEntityId";
    private static final String ALGO_PREFIX = "RS";
    private static final String ALGO_PREFIX_PS = "PS";
    
    public static String getTokenIdentifier(String tokenIdentifier, String consumerKey)
            throws IdentityOAuth2Exception {

        String accessTokenHash = tokenIdentifier;
        try {
            OauthTokenIssuer oauthTokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(consumerKey);
            //check for persist alias for the token type
            if (oauthTokenIssuer.usePersistedAccessTokenAlias()) {
                accessTokenHash = oauthTokenIssuer.getAccessTokenHash(tokenIdentifier);
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

    public static String[] getScopes(Object scopes) {

        if (scopes instanceof String) {
            return ((String) scopes).split(" ");
        }
        return new String[0];
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
    
    public static String getTenantDomain() {
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }
    
    public static boolean validateSignature(SignedJWT signedJWT, IdentityProvider idp)
            throws JOSEException, IdentityOAuth2Exception, ParseException {

        JWSVerifier verifier = null;
        X509Certificate x509Certificate = null;
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

        Map<String, String> realm = (HashMap) jwtClaimsSet.getClaim(OAuthConstants.OIDCClaims.REALM);

        // Get certificate from tenant if available in claims.
        if (MapUtils.isNotEmpty(realm)) {
            String tenantDomain = null;
            // Get signed key tenant from JWT token or ID token based on claim key.
            if (realm.get(OAuthConstants.OIDCClaims.SIGNING_TENANT) != null) {
                tenantDomain = realm.get(OAuthConstants.OIDCClaims.SIGNING_TENANT);
            } else if (realm.get(OAuthConstants.OIDCClaims.TENANT) != null) {
                tenantDomain = realm.get(OAuthConstants.OIDCClaims.TENANT);
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
     * The default implementation resolves one certificate to Identity Provider and ignores the JWT header.
     * Override this method, to resolve and enforce the certificate in any other way
     * such as x5t attribute of the header.
     *
     * @param idp    The identity provider, if you need it.
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
    
    public static String getUsernameFromUserID(String userId, String tenantDomain) {
        String username = null;
        AbstractUserStoreManager userStoreManager;
        try {
            userStoreManager = getUserStoreManager(tenantDomain);
            username = userStoreManager.getUserNameFromUserID(userId);
        } catch (IdentityOAuth2Exception | org.wso2.carbon.user.core.UserStoreException e) {
            // ignore throwring error.
            log.error("Error while retrieving user name from the userid ", e);
        }

        return username;
    }
    
    private static AbstractUserStoreManager getUserStoreManager(String tenantDomain)
            throws IdentityOAuth2Exception {

        int tenantId = getTenantId(tenantDomain);
        RealmService realmService = ServiceReferenceHolder.getInstance().getRealmService();
        AbstractUserStoreManager userStoreManager;
        try {
            userStoreManager
                    = (AbstractUserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Retrieved user store manager for tenant id: " + tenantId);
        }
        return userStoreManager;
    }

    private static int getTenantId(String tenantDomain) throws IdentityOAuth2Exception {

        int tenantId;
        try {
            tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        } catch (IdentityRuntimeException e) {
            log.error("Token request with Password Grant Type for an invalid tenant : " + tenantDomain);
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Retrieved tenant id: " + tenantId + " for tenant domain: " + tenantDomain);
        }
        return tenantId;
    }
    
    public static String getTenantAwareUsername(String username) {
        if (StringUtils.isNotBlank(username)) {
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            return UserCoreUtil.removeDomainFromName(tenantAwareUsername);
        }
        return null;
    }
}
