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

package org.wso2.is.key.manager.tokenpersistence.issuer;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.is.key.manager.tokenpersistence.PersistenceConstants;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;

/**
 * Extended JWT Token Issuer to extend issuing of refresh token in JWT format.
 */
public class ExtendedJWTTokenIssuer extends JWTTokenIssuer {
    private static final Log log = LogFactory.getLog(ExtendedJWTTokenIssuer.class);
    private final Algorithm signatureAlgorithm;

    public ExtendedJWTTokenIssuer() throws IdentityOAuth2Exception {

        OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();
        // Map signature algorithm from identity.xml to nimbus format, this is a one time configuration.
        signatureAlgorithm = mapSignatureAlgorithm(config.getSignatureAlgorithm());
    }

    @Override
    public String refreshToken(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext) throws OAuthSystemException {

        if (log.isDebugEnabled()) {
            log.debug("Refresh token request with authorization request message context message context. Authorized "
                    + "user " + oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getUser().getLoggableUserId());
        }
        try {
            return buildJWTTokenForRefreshTokens(oAuthAuthzReqMessageContext);
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthSystemException(e);
        }
    }

    @Override
    public String refreshToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {

        if (log.isDebugEnabled()) {
            log.debug("Refresh token request with token request message context. Authorized user "
                    + tokReqMsgCtx.getAuthorizedUser().getLoggableUserId());
        }
        try {
            return this.buildJWTTokenForRefreshTokens(tokReqMsgCtx);
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthSystemException(e);
        }
    }

    /**
     * Build a signed jwt token from Oauth authorization request message context.
     *
     * @param request Token request message context.
     * @return Signed jwt string.
     * @throws IdentityOAuth2Exception If an error occurred while building the jwt token.
     */
    protected String buildJWTTokenForRefreshTokens(OAuthAuthzReqMessageContext request)
            throws IdentityOAuth2Exception {

        // Set claims to jwt token.
        JWTClaimsSet jwtClaimsSet = createJWTClaimSetForRefreshTokens(request, null,
                request.getAuthorizationReqDTO().getConsumerKey());
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);

        if (request.getApprovedScope() != null && Arrays.asList((request.getApprovedScope())).contains(
                PersistenceConstants.JWTClaim.AUDIENCE)) {
            jwtClaimsSetBuilder.audience(Arrays.asList(request.getApprovedScope()));
        }
        jwtClaimsSet = jwtClaimsSetBuilder.build();
        if (JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName())) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }
        return signJWT(jwtClaimsSet, null, request);
    }

    /**
     * Build a signed jwt token from OauthToken request message context.
     *
     * @param request Token request message context.
     * @return Signed jwt string.
     * @throws IdentityOAuth2Exception If an error occurred while building the jwt token.
     */
    protected String buildJWTTokenForRefreshTokens(OAuthTokenReqMessageContext request)
            throws IdentityOAuth2Exception {

        // Set claims to jwt token.
        JWTClaimsSet jwtClaimsSet = createJWTClaimSetForRefreshTokens(null, request,
                request.getOauth2AccessTokenReqDTO().getClientId());
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);

        if (request.getScope() != null && Arrays.asList((request.getScope()))
                .contains(PersistenceConstants.JWTClaim.AUDIENCE)) {
            jwtClaimsSetBuilder.audience(Arrays.asList(request.getScope()));
        }
        jwtClaimsSet = jwtClaimsSetBuilder.build();
        if (JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName())) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }
        return signJWT(jwtClaimsSet, request, null);
    }

    /**
     * Create a JWT claim set according to the JWT format.
     *
     * @param authAuthzReqMessageContext Oauth authorization request message context.
     * @param tokenReqMessageContext     Token request message context.
     * @param consumerKey                Consumer key of the application.
     * @return JWT claim set.
     * @throws IdentityOAuth2Exception If an error occurred while creating the JWT claim set.
     */
    protected JWTClaimsSet createJWTClaimSetForRefreshTokens(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                                             OAuthTokenReqMessageContext tokenReqMessageContext,
                                                             String consumerKey) throws IdentityOAuth2Exception {

        // loading the stored application data.
        OAuthAppDO oAuthAppDO;
        String spTenantDomain;
        long refreshTokenLifeTimeInMillis;
        try {
            if (authAuthzReqMessageContext != null) {
                spTenantDomain = authAuthzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();
            } else {
                spTenantDomain = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain();
            }
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: " + consumerKey, e);
        }
        String issuer = OAuth2Util.getIdTokenIssuer(spTenantDomain);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(authAuthzReqMessageContext, tokenReqMessageContext);
        String sub = getSubjectClaim(authenticatedUser);
        // Set the default claims.
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issuer(issuer);
        jwtClaimsSetBuilder.subject(sub);
        jwtClaimsSetBuilder.claim(PersistenceConstants.JWTClaim.AUTHORIZATION_PARTY, consumerKey);
        if (tokenReqMessageContext != null) {
            refreshTokenLifeTimeInMillis = getRefreshTokenLifeTimeInMillis(oAuthAppDO, tokenReqMessageContext);
        } else {
            refreshTokenLifeTimeInMillis = getRefreshTokenLifeTimeInMillis(oAuthAppDO, authAuthzReqMessageContext);
        }
        long curTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(PersistenceConstants.UTC)).getTimeInMillis();
        Date issuedTime = new Date(curTimeInMillis);
        jwtClaimsSetBuilder.issueTime(getRefreshTokenIssuedTime(tokenReqMessageContext, oAuthAppDO, issuedTime));
        jwtClaimsSetBuilder.expirationTime(
                calculateRefreshTokenExpiryTime(refreshTokenLifeTimeInMillis, curTimeInMillis));
        jwtClaimsSetBuilder.jwtID(UUID.randomUUID().toString());
        jwtClaimsSetBuilder.claim(PersistenceConstants.JWTClaim.CLIENT_ID, consumerKey);
        String scope = getScope(authAuthzReqMessageContext, tokenReqMessageContext, sub);
        if (StringUtils.isNotEmpty(scope)) {
            jwtClaimsSetBuilder.claim(PersistenceConstants.JWTClaim.SCOPE, scope);
        }
        // claim to identify the JWT as a refresh token.
        jwtClaimsSetBuilder.claim(PersistenceConstants.JWTClaim.TOKEN_TYPE_ELEM, PersistenceConstants.REFRESH_TOKEN);
        /*
         * This is a spec (openid-connect-core-1_0:2.0) requirement for ID tokens. But we are keeping this in JWT as
         * well.
         */
        List<String> audience = OAuth2Util.getOIDCAudience(consumerKey, oAuthAppDO);
        jwtClaimsSetBuilder.audience(audience);
        setClaimsForNonPersistence(jwtClaimsSetBuilder, authAuthzReqMessageContext, tokenReqMessageContext,
                authenticatedUser, oAuthAppDO);
        return jwtClaimsSetBuilder.build();
    }

    /**
     * Get token validity period for the Self contained JWT Access Token from OAuthApp or OAuthServer Configuration.
     *
     * @param oAuthAppDO OAuthApp
     * @return Refresh Token Life Time in milliseconds
     */
    private long getRefreshTokenLifeTimeInMillisFromConfig(OAuthAppDO oAuthAppDO) {

        String consumerKey = oAuthAppDO.getOauthConsumerKey();
        long refreshTokenValidityPeriodInMillis;
        if (oAuthAppDO.getRefreshTokenExpiryTime() != 0) {
            refreshTokenValidityPeriodInMillis =
                    oAuthAppDO.getRefreshTokenExpiryTime() * PersistenceConstants.SECONDS_TO_MILLISECONDS_FACTOR;
            if (log.isDebugEnabled()) {
                log.debug("OAuth application id : " + consumerKey + ", refresh token validity time " +
                        refreshTokenValidityPeriodInMillis + "ms");
            }
        } else {
            refreshTokenValidityPeriodInMillis = OAuthServerConfiguration.getInstance()
                    .getRefreshTokenValidityPeriodInSeconds() * PersistenceConstants.SECONDS_TO_MILLISECONDS_FACTOR;
        }
        return refreshTokenValidityPeriodInMillis;
    }

    /**
     * Get token validity period for the Self contained JWT Access Token.
     *
     * @param oAuthAppDO             OAuthApp
     * @param tokenReqMessageContext TokenRequestMessageContext
     * @return Refresh Token Life Time in milliseconds
     */
    private long getRefreshTokenLifeTimeInMillis(OAuthAppDO oAuthAppDO,
                                                 OAuthTokenReqMessageContext tokenReqMessageContext) {

        String consumerKey = oAuthAppDO.getOauthConsumerKey();
        long refreshTokenValidityPeriodInMillis = 0;
        long validityPeriodFromMsgContext = tokenReqMessageContext.getRefreshTokenvalidityPeriod();
        if (validityPeriodFromMsgContext > 0) {
            refreshTokenValidityPeriodInMillis = validityPeriodFromMsgContext *
                    PersistenceConstants.SECONDS_TO_MILLISECONDS_FACTOR;
            if (log.isDebugEnabled()) {
                log.debug("OAuth application id : " + consumerKey + ", using refresh token " +
                        "validity period configured from OAuthTokenReqMessageContext: " +
                        refreshTokenValidityPeriodInMillis + " ms");
            }
        } else if (tokenReqMessageContext.getProperty(PersistenceConstants.PREV_ACCESS_TOKEN) != null) {
            RefreshTokenValidationDataDO validationBean =
                    (RefreshTokenValidationDataDO) tokenReqMessageContext.getProperty(
                            PersistenceConstants.PREV_ACCESS_TOKEN);
            if (isRenewRefreshToken(oAuthAppDO.getRenewRefreshTokenEnabled())
                    && !OAuthServerConfiguration.getInstance().isExtendRenewedTokenExpiryTimeEnabled()) {
                // If refresh token renewal enabled and extend token expiry disabled, set the old token issued and
                // validity.
                refreshTokenValidityPeriodInMillis = validationBean.getValidityPeriodInMillis();
            }
        }
        if (refreshTokenValidityPeriodInMillis == 0) {
            refreshTokenValidityPeriodInMillis = getRefreshTokenLifeTimeInMillisFromConfig(oAuthAppDO);
        }
        if (log.isDebugEnabled()) {
            log.debug("JWT Self Signed Refresh Token Life time set to : " + refreshTokenValidityPeriodInMillis + "ms.");
        }
        return refreshTokenValidityPeriodInMillis;
    }

    /**
     * Get token validity period for the Self contained JWT Access Token.
     *
     * @param oAuthAppBean     OAuthApp
     * @param oauthAuthzMsgCtx OAuthAuthhorizationRequestMessageContext
     * @return Refresh Token Life Time in milliseconds
     */
    private long getRefreshTokenLifeTimeInMillis(OAuthAppDO oAuthAppBean,
                                                 OAuthAuthzReqMessageContext oauthAuthzMsgCtx) {

        long refreshTokenValidityPeriodInMillis = 0;
        long refreshTokenValidityPeriod = oauthAuthzMsgCtx.getRefreshTokenvalidityPeriod();
        if (refreshTokenValidityPeriod > 0) {
            refreshTokenValidityPeriodInMillis = oauthAuthzMsgCtx.getRefreshTokenvalidityPeriod() *
                    PersistenceConstants.SECONDS_TO_MILLISECONDS_FACTOR;
            if (log.isDebugEnabled()) {
                log.debug("OAuth application id : " + oAuthAppBean.getOauthConsumerKey() + ", using refresh token " +
                        "validity period configured from OAuthAuthzReqMessageContext: " +
                        refreshTokenValidityPeriodInMillis + " ms");
            }
        }
        if (refreshTokenValidityPeriodInMillis == 0) {
            refreshTokenValidityPeriodInMillis = getRefreshTokenLifeTimeInMillisFromConfig(oAuthAppBean);
        }
        if (log.isDebugEnabled()) {
            log.debug("JWT Self Signed Refresh Token Life time set to : " + refreshTokenValidityPeriodInMillis + "ms.");
        }
        return refreshTokenValidityPeriodInMillis;
    }

    private Date getRefreshTokenIssuedTime(OAuthTokenReqMessageContext tokenReqMessageContext,
                                           OAuthAppDO oAuthAppDO, Date currentTime) {

        Date refreshTokenIssuedTime = currentTime;
        if (tokenReqMessageContext != null &&
                tokenReqMessageContext.getProperty(PersistenceConstants.PREV_ACCESS_TOKEN) != null) {
            RefreshTokenValidationDataDO validationBean =
                    (RefreshTokenValidationDataDO) tokenReqMessageContext.getProperty(
                            PersistenceConstants.PREV_ACCESS_TOKEN);
            if (isRenewRefreshToken(oAuthAppDO.getRenewRefreshTokenEnabled()) &&
                    !OAuthServerConfiguration.getInstance().isExtendRenewedTokenExpiryTimeEnabled()) {
                // If refresh token renewal enabled and extend token expiry disabled, set the old token issued and
                // validity.
                refreshTokenIssuedTime = validationBean.getIssuedTime();
            }
            if (refreshTokenIssuedTime == null) {
                refreshTokenIssuedTime = currentTime;
            }
        }
        return refreshTokenIssuedTime;
    }

    private boolean isRenewRefreshToken(String renewRefreshToken) {

        if (StringUtils.isNotBlank(renewRefreshToken)) {
            if (log.isDebugEnabled()) {
                log.debug("Reading the Oauth application specific renew " +
                        "refresh token value as " + renewRefreshToken + " from the IDN_OIDC_PROPERTY table");
            }
            return Boolean.parseBoolean(renewRefreshToken);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Reading the global renew refresh token value from the identity.xml");
            }
            return OAuthServerConfiguration.getInstance().isRefreshTokenRenewalEnabled();
        }
    }

    /**
     * Get authentication request object from message context.
     *
     * @param authAuthzReqMessageContext OAuthAuthzReqMessageContext
     * @param tokenReqMessageContext     OAuthTokenReqMessageContext
     * @return AuthenticatedUser    Authenticated user
     */
    protected AuthenticatedUser getAuthenticatedUser(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                                     OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        AuthenticatedUser authenticatedUser;
        if (authAuthzReqMessageContext != null) {
            authenticatedUser = authAuthzReqMessageContext.getAuthorizationReqDTO().getUser();
        } else {
            authenticatedUser = tokenReqMessageContext.getAuthorizedUser();
        }
        if (authenticatedUser == null) {
            throw new IdentityOAuth2Exception("Authenticated user is null for the request.");
        }
        return authenticatedUser;
    }

    /**
     * To get the scope of the token to be added to the JWT claims.
     *
     * @param authAuthzReqMessageContext Auth Request Message Context
     * @param tokenReqMessageContext     Token Request Message Context
     * @param subject                    Subject Identifier
     * @return scope of token.
     */
    protected String getScope(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                              OAuthTokenReqMessageContext tokenReqMessageContext, String subject) {

        String[] scope;
        String scopeString = null;
        if (tokenReqMessageContext != null) {
            scope = tokenReqMessageContext.getScope();
        } else {
            scope = authAuthzReqMessageContext.getApprovedScope();
        }
        if (ArrayUtils.isNotEmpty(scope)) {
            scopeString = OAuth2Util.buildScopeString(scope);
            if (log.isDebugEnabled()) {
                log.debug("Scope exist for the jwt access token with subject " + subject + " and the scope is "
                        + scopeString);
            }
        }
        return scopeString;
    }

    /**
     * To get authenticated subject identifier.
     *
     * @param authenticatedUser Authorized User
     * @return authenticated subject identifier.
     */
    protected String getSubjectClaim(AuthenticatedUser authenticatedUser) {

        return authenticatedUser.getAuthenticatedSubjectIdentifier();
    }

    /**
     * Calculates refresh token expiry time.
     *
     * @param refreshTokenLifeTimeInMillis refreshTokenLifeTimeInMillis
     * @param curTimeInMillis              currentTimeInMillis
     * @return expirationTime
     */
    private Date calculateRefreshTokenExpiryTime(Long refreshTokenLifeTimeInMillis, Long curTimeInMillis) {

        Date expirationTime;
        // When refreshTokenLifeTimeInMillis is equal to Long.MAX_VALUE the curTimeInMillis +
        // accessTokenLifeTimeInMillis can be a negative value
        if (curTimeInMillis + refreshTokenLifeTimeInMillis < curTimeInMillis) {
            expirationTime = new Date(Long.MAX_VALUE);
        } else {
            expirationTime = new Date(curTimeInMillis + refreshTokenLifeTimeInMillis);
        }
        if (log.isDebugEnabled()) {
            log.debug("Refresh token expiry time : " + expirationTime + "ms.");
        }
        return expirationTime;
    }
}
