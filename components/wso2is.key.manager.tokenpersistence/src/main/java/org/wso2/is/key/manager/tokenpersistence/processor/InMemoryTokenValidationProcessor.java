/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenValidationProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;
import org.wso2.is.key.manager.tokenpersistence.PersistenceConstants;
import org.wso2.is.key.manager.tokenpersistence.internal.ServiceReferenceHolder;
import org.wso2.is.key.manager.tokenpersistence.utils.TokenMgtUtil;

import java.sql.Timestamp;
import java.text.ParseException;
import java.util.Date;

/**
 * Default token validation processor with token persistence.
 */
public class InMemoryTokenValidationProcessor implements TokenValidationProcessor {


    private static final Log log = LogFactory.getLog(InMemoryTokenValidationProcessor.class);

    public AccessTokenDO validateToken(OAuth2TokenValidationMessageContext messageContext,
                                       OAuth2TokenValidationRequestDTO validationRequestDTO, boolean includeExpired)
            throws IdentityOAuth2Exception {

        /*
         * not checking for invalid refresh tokens as refresh tokens do not require the same level of real-time
         * validation as access tokens.
         */
        // check if token is JWT.
        if (OAuth2Util.isJWT(validationRequestDTO.getAccessToken().getIdentifier())) {
            //validate JWT token signature, expiry time, not before time
            try {
                SignedJWT signedJWT = SignedJWT.parse(validationRequestDTO.getAccessToken().getIdentifier());
                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
                if (claimsSet == null) {
                    throw new IdentityOAuth2Exception("Claim values are empty in the given Token.");
                }
                IdentityProvider identityProvider = TokenMgtUtil.getResidentIDPForIssuer(claimsSet.getIssuer());
                if (!TokenMgtUtil.validateSignature(signedJWT, identityProvider)) {
                    throw new IdentityOAuth2Exception(("Invalid signature"));
                }
                boolean isTokenActive = true;
                if (!TokenMgtUtil.isActive(claimsSet.getExpirationTime())) {
                    if (!includeExpired) {
                        throw new IdentityOAuth2Exception("Invalid token. Expiry time exceeded");
                    }
                    isTokenActive = false;
                }
                checkNotBeforeTime(claimsSet.getNotBeforeTime());
                String consumerKey = (String) claimsSet.getClaim("azp");
                // check whether the token is already revoked through direct revocations
                if (ServiceReferenceHolder.getInvalidTokenPersistenceService().isInvalidToken(
                        TokenMgtUtil.getTokenIdentifier(validationRequestDTO.getAccessToken().getIdentifier(),
                                consumerKey),
                        PersistenceConstants.TOKEN_TYPE_ACCESS_TOKEN, consumerKey)) {
                    throw new IllegalArgumentException("Invalid Access Token. ACTIVE access token is not found.");
                }
                //TODO:// check whether the token is already revoked through indirect revocations
                //validate token against persisted invalid refresh tokens
                Object scopes = claimsSet.getClaim("scope");

                //create new AccessTokenDO
                AccessTokenDO validationDataDO = new AccessTokenDO();
                validationDataDO.setConsumerKey(consumerKey);
                validationDataDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
                validationDataDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                        - claimsSet.getIssueTime().getTime());
                validationDataDO.setScope(TokenMgtUtil.getScopes(scopes));
                //TODO:// identify the user from the userId in subject claim ?
                AuthenticatedUser user = OAuth2Util.getUserFromUserName(claimsSet.getSubject());
                user.setAuthenticatedSubjectIdentifier(claimsSet.getSubject());
                validationDataDO.setAuthzUser(user);
                if (isTokenActive) {
                    validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
                } else {
                    validationDataDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
                }
                OAuthUtil.clearOAuthCache(consumerKey, user, OAuth2Util.buildScopeString(validationDataDO.getScope()),
                        "NONE");
                return validationDataDO;
            } catch (JOSEException | ParseException e) {
                throw new IdentityOAuth2Exception("Error while validating Token.", e);
            }
        }
        return null;
    }

    private boolean checkNotBeforeTime(Date notBeforeTime) throws IdentityOAuth2Exception {

        if (notBeforeTime != null) {
            long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
            long notBeforeTimeMillis = notBeforeTime.getTime();
            long currentTimeInMillis = System.currentTimeMillis();
            if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
                if (log.isDebugEnabled()) {
                    log.debug("Token is used before Not_Before_Time." +
                            ", Not Before Time(ms) : " + notBeforeTimeMillis +
                            ", TimeStamp Skew : " + timeStampSkewMillis +
                            ", Current Time : " + currentTimeInMillis + ". Token Rejected and validation terminated.");
                }
                throw new IdentityOAuth2Exception("Token is used before Not_Before_Time.");
            }
            if (log.isDebugEnabled()) {
                log.debug("Not Before Time(nbf) of Token was validated successfully.");
            }
        }
        return true;
    }
}
