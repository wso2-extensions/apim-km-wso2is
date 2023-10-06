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
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenValidationProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.is.key.manager.tokenpersistence.PersistenceConstants;
import org.wso2.is.key.manager.tokenpersistence.utils.TokenMgtUtil;

import java.sql.Timestamp;

/**
 * In Memory token validation processor for in memory token persistence. Token Validation processor is supposed to be
 * used during token introspection and user info endpoints where you need to validate the token before proceeding.
 */
public class InMemoryTokenValidationProcessor implements TokenValidationProcessor {

    private static final Log log = LogFactory.getLog(InMemoryTokenValidationProcessor.class);

    public AccessTokenDO validateToken(String token, boolean includeExpired)
            throws IdentityOAuth2Exception {

        // check if token is JWT.
        TokenMgtUtil.isJWTToken(token);
        log.debug(String.format("Validating JWT Token with expiry %s", includeExpired));
        // validate JWT token signature, expiry time, not before time.
        SignedJWT signedJWT = TokenMgtUtil.parseJWT(token);
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet);
        // expiry time verification.
        boolean isTokenActive = true;
        if (!TokenMgtUtil.isActive(claimsSet.getExpirationTime())) {
            if (!includeExpired) {
                throw new IdentityOAuth2Exception("Invalid token. Expiry time exceeded.");
            }
            isTokenActive = false;
        }
        // not before time verification.
        TokenMgtUtil.checkNotBeforeTime(claimsSet.getNotBeforeTime());
        String consumerKey = (String) claimsSet.getClaim(PersistenceConstants.AUTHORIZATION_PARTY);
        /*
         * check whether the token is already revoked through direct revocations and following indirect
         * revocations.
         * 1. check if consumer app was changed.
         * 2. check if user was changed.
         */
        if (TokenMgtUtil.isTokenRevokedDirectly(token, consumerKey)
                || TokenMgtUtil.isTokenRevokedIndirectly(claimsSet.getSubject(), consumerKey,
                claimsSet.getIssueTime())) {
            throw new IllegalArgumentException("Invalid Access Token. ACTIVE access token is not found.");
        }
        Object scopes = claimsSet.getClaim(PersistenceConstants.SCOPE);
        // create new AccessTokenDO with validated token information.
        AccessTokenDO validationDataDO = new AccessTokenDO();
        validationDataDO.setConsumerKey(consumerKey);
        validationDataDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
        validationDataDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                - claimsSet.getIssueTime().getTime());
        validationDataDO.setScope(TokenMgtUtil.getScopes(scopes));
        AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
        validationDataDO.setAuthzUser(authenticatedUser);
        if (isTokenActive) {
            log.debug("Token is active");
            validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        } else {
            log.debug("Token is expired");
            validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
        }
        validationDataDO.setAccessToken(TokenMgtUtil.getTokenIdentifier(token, consumerKey));
        //TODO:// handle oauth caching
        return validationDataDO;
    }
}
