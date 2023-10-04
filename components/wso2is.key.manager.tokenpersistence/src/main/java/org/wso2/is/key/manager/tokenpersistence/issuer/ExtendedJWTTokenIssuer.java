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
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.is.key.manager.tokenpersistence.PersistenceConstants;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

/**
 * Extended JWT Token Issuer to extend issuing of refresh token in JWT format.
 */
public class ExtendedJWTTokenIssuer extends JWTTokenIssuer {
    private static final Log log = LogFactory.getLog(ExtendedJWTTokenIssuer.class);
    private static final String AUDIENCE = "aud";
    private static final String CLIENT_ID = "client_id";
    private static final String SCOPE = "scope";
    private static final String GIVEN_NAME = "given_name";
    private Algorithm signatureAlgorithm;

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

        if (request.getApprovedScope() != null && Arrays.asList((request.getApprovedScope())).contains(AUDIENCE)) {
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

        if (request.getScope() != null && Arrays.asList((request.getScope())).contains(AUDIENCE)) {
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

        // loading the stored application data
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: " + consumerKey, e);
        }
        long refreshTokenLifeTimeInMillis = getRefreshTokenLifeTimeInMillis(oAuthAppDO);
        String spTenantDomain;
        if (authAuthzReqMessageContext != null) {
            spTenantDomain = authAuthzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();
        } else {
            spTenantDomain = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain();
        }
        String issuer = OAuth2Util.getIdTokenIssuer(spTenantDomain);
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();

        String sub = getAuthenticatedSubjectIdentifier(authAuthzReqMessageContext, tokenReqMessageContext);
        if (StringUtils.isEmpty(sub)) {
            sub = getAuthenticatedUser(authAuthzReqMessageContext, tokenReqMessageContext).toFullQualifiedUsername();
        }
        // Set the default claims.
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issuer(issuer);
        jwtClaimsSetBuilder.subject(sub);
        jwtClaimsSetBuilder.claim(PersistenceConstants.AUTHORIZATION_PARTY, consumerKey);
        jwtClaimsSetBuilder.issueTime(new Date(curTimeInMillis));
        jwtClaimsSetBuilder.jwtID(UUID.randomUUID().toString());
        jwtClaimsSetBuilder.notBeforeTime(new Date(curTimeInMillis));
        jwtClaimsSetBuilder.claim(CLIENT_ID, consumerKey);
        // TODO: check whether we need the user name in the refresh token. we can derive it using the userID as well.
        jwtClaimsSetBuilder.claim(GIVEN_NAME,
                getAuthenticatedUser(authAuthzReqMessageContext, tokenReqMessageContext).toFullQualifiedUsername());
        jwtClaimsSetBuilder.claim(PersistenceConstants.TOKEN_TYPE_ELEM, PersistenceConstants.REFRESH_TOKEN);

        String scope = getScope(authAuthzReqMessageContext, tokenReqMessageContext);
        if (StringUtils.isNotEmpty(scope)) {
            jwtClaimsSetBuilder.claim(SCOPE, scope);
        }

        jwtClaimsSetBuilder.expirationTime(new Date(curTimeInMillis + refreshTokenLifeTimeInMillis));
        return jwtClaimsSetBuilder.build();
    }

    /**
     * Get token validity period for the Self contained JWT Access Token.
     *
     * @param oAuthAppDO OAuthApp
     * @return Refresh Token Life Time in milliseconds
     */
    protected long getRefreshTokenLifeTimeInMillis(OAuthAppDO oAuthAppDO) {

        long lifetimeInMillis;
        if (oAuthAppDO.getRefreshTokenExpiryTime() != 0) {
            lifetimeInMillis = oAuthAppDO.getRefreshTokenExpiryTime() * 1000;
            if (log.isDebugEnabled()) {
                log.debug("Refresh Token Life time set to : " + lifetimeInMillis + "ms.");
            }
        } else {
            lifetimeInMillis = OAuthServerConfiguration.getInstance()
                    .getRefreshTokenValidityPeriodInSeconds() * 1000;
            if (log.isDebugEnabled()) {
                log.debug("Application access token time was 0ms. Setting default refresh token " +
                        "lifetime : " + lifetimeInMillis + "ms.");
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("JWT Self Signed Refresh Token Life time set to : " + lifetimeInMillis + "ms.");
        }
        return lifetimeInMillis;
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
     * @param authAuthzReqMessageContext Auth Request Message Context.
     * @param tokenReqMessageContext     Token Request Message Context.
     * @return scope of token.
     */
    protected String getScope(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                              OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {

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
                log.debug("Scope exist for the jwt access token with subject " + getAuthenticatedSubjectIdentifier(
                        authAuthzReqMessageContext, tokenReqMessageContext) + " and the scope is " + scopeString);
            }
        }
        return scopeString;
    }

    /**
     * To get authenticated subject identifier.
     *
     * @param authAuthzReqMessageContext Auth Request Message Context.
     * @param tokenReqMessageContext     Token request message context.
     * @return authenticated subject identifier.
     */
    protected String getAuthenticatedSubjectIdentifier(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                                       OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(authAuthzReqMessageContext, tokenReqMessageContext);
        return authenticatedUser.getAuthenticatedSubjectIdentifier();
    }
}
