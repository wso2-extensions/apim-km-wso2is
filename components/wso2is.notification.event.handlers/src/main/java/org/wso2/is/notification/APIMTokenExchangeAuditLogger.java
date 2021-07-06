/*
 *   Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.is.notification;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.logging.Log;
import org.json.JSONObject;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.is.notification.NotificationConstants.AuditLogConstants;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import static org.wso2.carbon.CarbonConstants.AUDIT_LOG;

/**
 * APIM Token Exchange Audit Logger Interceptor Implementation
 */
public class APIMTokenExchangeAuditLogger extends AbstractOAuthEventInterceptor {

    private static final Log audit = AUDIT_LOG;

    public APIMTokenExchangeAuditLogger() {

        super.init(initConfig);
    }

    /**
     * Audit Logs the exchanged token information for token exchange flow in success scenario
     *
     * @param tokenReqDTO  Token Request DTO
     * @param tokenRespDTO Token Response DTO
     * @param tokReqMsgCtx Oauth Token Request Message Context
     * @param params       HTTP Request Parameters
     */
    @Override
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                 OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) {

        if (!isTokenExchangeGrant(tokenReqDTO)) {
            return;
        }

        if (isTokenRequestSuccessful(tokenRespDTO)) {
            JSONObject entityInfo = constructEntityInfo(tokenReqDTO, tokenRespDTO);
            logAuditMessage(entityInfo, tokReqMsgCtx.getAuthorizedUser().getUserName());
        }
    }

    private static void logAuditMessage(JSONObject entityInfo, String performedBy) {

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("typ", AuditLogConstants.TOKEN_GENERATION);
        jsonObject.put("action", AuditLogConstants.TOKEN_EXCHANGE);
        jsonObject.put("performedBy", performedBy);
        jsonObject.put("info", entityInfo);
        audit.info(StringEscapeUtils.unescapeJava(jsonObject.toString()));
    }

    private static Map<String, String> getRequestParams(RequestParameter[] params) {

        return Arrays.stream(params).collect(Collectors.toMap(RequestParameter::getKey,
                requestParam -> requestParam.getValue()[0]));
    }

    private static JSONObject getJWTClaims(String jwtToken) {

        JSONObject entityInfo = new JSONObject();
        try {
            if (StringUtils.isNotEmpty(jwtToken)) {
                SignedJWT signedJWT = SignedJWT.parse(jwtToken);
                if (signedJWT.getJWTClaimsSet() != null) {
                    JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
                    entityInfo.put(AuditLogConstants.ISSUER, claimsSet.getIssuer());
                    entityInfo.put(AuditLogConstants.AUDIENCE, claimsSet.getAudience());
                    entityInfo.put(AuditLogConstants.JWT_ID, claimsSet.getJWTID());
                    entityInfo.put(AuditLogConstants.ISSUED_AT, claimsSet.getIssueTime().getTime());
                }
            }
        } catch (ParseException ignore) {
        }
        return entityInfo;
    }

    private static boolean isJWT(String subjectTokenType, String subjectToken) {

        return AuditLogConstants.JWT_TOKEN_TYPE.equals(subjectTokenType) ||
                (AuditLogConstants.ACCESS_TOKEN_TYPE.equals(subjectTokenType)
                        && OAuth2Util.isJWT(subjectToken));
    }

    private static boolean isTokenExchangeGrant(OAuth2AccessTokenReqDTO tokenReqDTO) {

        return AuditLogConstants.TOKEN_EXCHANGE_GRANT.equals(tokenReqDTO.getGrantType());
    }

    private boolean isTokenRequestSuccessful(OAuth2AccessTokenRespDTO tokenRespDTO) {

        return !tokenRespDTO.isError();
    }

    private static String getRequestedTokenType(Map<String, String> requestParams) {

        if (requestParams.get(AuditLogConstants.REQUESTED_TOKEN_TYPE) != null) {
            return requestParams.get(AuditLogConstants.REQUESTED_TOKEN_TYPE);
        } else {
            return AuditLogConstants.JWT_TOKEN_TYPE;
        }
    }

    private static JSONObject constructEntityInfo(OAuth2AccessTokenReqDTO tokenReqDTO,
                                                  OAuth2AccessTokenRespDTO tokenRespDTO) {

        JSONObject entityInfo = new JSONObject();
        Map<String, String> requestParams = getRequestParams(tokenReqDTO.getRequestParameters());
        entityInfo.put(AuditLogConstants.CLIENT_ID, tokenReqDTO.getClientId());
        entityInfo.put(AuditLogConstants.GRANT_TYPE, tokenReqDTO.getGrantType());
        entityInfo.put(AuditLogConstants.REQUESTED_TOKEN_TYPE, getRequestedTokenType(requestParams));
        if (isJWT(requestParams.get(AuditLogConstants.SUBJECT_TOKEN_TYPE), requestParams
                .get(AuditLogConstants.SUBJECT_TOKEN))) {
            entityInfo.put("subject_token_info", getJWTClaims(requestParams.get(AuditLogConstants.SUBJECT_TOKEN)));
        }
        entityInfo.put("issued_token_info", getJWTClaims(tokenRespDTO.getAccessToken()));
        return entityInfo;
    }
}
