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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.tokenprocessor.OAuth2RevocationProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.is.key.manager.tokenpersistence.internal.ServiceReferenceHolder;
import org.wso2.is.key.manager.tokenpersistence.utils.TokenMgtUtil;

/**
 * Token revocation related implementation for InMemory persistence.
 */
public class InMemoryOAuth2RevocationProcessor implements OAuth2RevocationProcessor {

    private static final Log log = LogFactory.getLog(InMemoryOAuth2RevocationProcessor.class);

    @Override
    public void revokeAccessToken(OAuthRevocationRequestDTO revokeRequestDTO, AccessTokenDO accessTokenDO)
            throws IdentityOAuth2Exception {

        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
        ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService().addInvalidToken(
                accessTokenDO.getAccessToken(), accessTokenDO.getConsumerKey(), accessTokenDO.getIssuedTime().getTime()
                        + accessTokenDO.getValidityPeriodInMillis());
    }

    @Override
    public void revokeRefreshToken(OAuthRevocationRequestDTO revokeRequestDTO,
                                   RefreshTokenValidationDataDO refreshTokenDO) throws IdentityOAuth2Exception {

        String tokenIdentifier = OAuth2Util.isJWT(revokeRequestDTO.getToken()) ?
                TokenMgtUtil.getTokenIdentifier(revokeRequestDTO.getToken(), revokeRequestDTO.getConsumerKey()) :
                revokeRequestDTO.getToken();
        refreshTokenDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
        ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService().addInvalidToken(
                tokenIdentifier, revokeRequestDTO.getConsumerKey(), refreshTokenDO.getIssuedTime().getTime()
                        + refreshTokenDO.getValidityPeriodInMillis());
    }

//    @Override
//    public RefreshTokenValidationDataDO getRevocableRefreshToken(OAuthRevocationRequestDTO revokeRequestDTO)
//            throws IdentityOAuth2Exception {
//
//        RefreshTokenValidationDataDO validationDataDO = null;
//        if (!OAuth2Util.isJWT(revokeRequestDTO.getToken())) {
//            log.debug("Refresh token is not a JWT. Hence, validating as an opaque token from database.");
//            // For backward compatibility, we check whether it is available in idn_oauth2_token table.
//            RefreshTokenValidationDataDO validationDO = OpaqueTokenUtil.validateOpaqueRefreshToken(revokeRequestDTO);
//            OAuthUtil.clearOAuthCache(revokeRequestDTO.getConsumerKey(), validationDO.getAuthorizedUser(),
//                    OAuth2Util.buildScopeString(validationDO.getScope()), "NONE");
//            return validationDO;
//        }
//        SignedJWT signedJWT = TokenMgtUtil.parseJWT(revokeRequestDTO.getToken());
//        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
//        TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet);
//        String consumerKey = (String) claimsSet.getClaim(PersistenceConstants.AUTHORIZATION_PARTY);
//        // validate consumer key in the request against the token.
//        if (!revokeRequestDTO.getConsumerKey().equals(consumerKey)) {
//            throw new IdentityOAuth2Exception("Invalid refresh token. Consumer key does not match.");
//        }
//        /*
//         * check whether the token is not already revoked through direct revocations and following indirect
//         * revocations.
//         * 1. check if consumer app was changed.
//         * 2. check if user was changed.
//         */
//        if (!TokenMgtUtil.isTokenRevokedDirectly(revokeRequestDTO.getToken(), consumerKey)
//                && !TokenMgtUtil.isTokenRevokedIndirectly(claimsSet)) {
//            validationDataDO = new RefreshTokenValidationDataDO();
//            // set expiration state according to jwt claim in it.
//            if (TokenMgtUtil.isActive(claimsSet.getExpirationTime())) {
//                validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
//            } else {
//                validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
//            }
//            // set other fields from jwt claims.
//            validationDataDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
//            validationDataDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
//                    - claimsSet.getIssueTime().getTime());
//            validationDataDO.setScope(TokenMgtUtil.getScopes(claimsSet.getClaim(PersistenceConstants.SCOPE)));
//            AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
//            validationDataDO.setAuthorizedUser(authenticatedUser);
//        }
//        return validationDataDO;
//    }

//    @Override
//    public AccessTokenDO getRevocableAccessToken(OAuthRevocationRequestDTO revokeRequestDTO)
//            throws IdentityOAuth2Exception {
//
//        AccessTokenDO accessTokenDO = null;
//        TokenMgtUtil.isJWTToken(revokeRequestDTO.getToken());
//        SignedJWT signedJWT = TokenMgtUtil.parseJWT(revokeRequestDTO.getToken());
//        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
//        TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet);
//        String consumerKey = (String) claimsSet.getClaim(PersistenceConstants.AUTHORIZATION_PARTY);
//        // validate consumer key in the request against the token.
//        if (!revokeRequestDTO.getConsumerKey().equals(consumerKey)) {
//            throw new IdentityOAuth2Exception("Invalid refresh token. Consumer key does not match.");
//        }
//        String accessTokenIdentifier = TokenMgtUtil.getTokenIdentifier(claimsSet);
//        /*
//         * check whether the token is not already revoked through direct revocations and following indirect
//         * revocations, if so return nothing.
//         * 1. check if consumer app was changed.
//         * 2. check if user was changed.
//         */
//        if (!TokenMgtUtil.isTokenRevokedDirectly(accessTokenIdentifier, consumerKey)
//                && !TokenMgtUtil.isTokenRevokedIndirectly(claimsSet)) {
//            Optional<AccessTokenDO> tokenDO = TokenMgtUtil.getTokenDOFromCache(accessTokenIdentifier);
//            if (tokenDO.isPresent()) {
//                accessTokenDO = tokenDO.get();
//                if (log.isDebugEnabled()) {
//                    log.debug("Retrieved active access token from OAuthCache for token Identifier: " +
//                            accessTokenDO.getTokenId());
//                }
//            } else {
//                // cache miss, load the access token info from the database.
//                accessTokenDO = new AccessTokenDO();
//                String tokenId = UUID.randomUUID().toString();
//                accessTokenDO.setTokenId(tokenId); //TODO: check if we really need this
//                accessTokenDO.setAccessToken(accessTokenIdentifier);
//                accessTokenDO.setConsumerKey(consumerKey);
//                // check if token is expired and set tokenState EXPIRED or ACTIVE.
//                if (TokenMgtUtil.isActive(claimsSet.getExpirationTime())) {
//                    accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
//                } else {
//                    accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
//                }
//                // TODO:// need to decide how to determine the consented state for the previous access token or
//                if previous
//                accessTokenDO.setIsConsentedToken(false);
//                // set other fields from jwt claims.
//                accessTokenDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
//                accessTokenDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
//                        - claimsSet.getIssueTime().getTime());
//                accessTokenDO.setScope(TokenMgtUtil.getScopes(claimsSet.getClaim(PersistenceConstants.SCOPE)));
//                AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
//                accessTokenDO.setAuthzUser(authenticatedUser);
//                // Add the token back to the cache in the case of a cache miss.
//                TokenMgtUtil.addTokenToCache(accessTokenIdentifier, accessTokenDO);
//            }
//        }
//        return accessTokenDO;
//    }

    @Override
    public boolean revokeTokens(String username, UserStoreManager userStoreManager) throws UserStoreException {
        return false;
    }
}
