/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.is.key.manager.operations.endpoint.impl;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.user.api.ClaimManager;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.UserRealmService;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.is.key.manager.operations.endpoint.UserInfoApiService;
import org.wso2.is.key.manager.operations.endpoint.dto.ClaimRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.userinfo.util.UserInfoUtil;

import java.util.HashMap;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.ws.rs.core.Response;

import static org.apache.commons.collections.MapUtils.isNotEmpty;

/**
 * Service Implementation for Claims API.
 */
public class UserInfoApiServiceImpl implements UserInfoApiService {

    private static final Log log = LogFactory.getLog(UserInfoApiServiceImpl.class);
    private static final String DEFAULT_DIALECT_URI = "http://wso2.org/claims";

    @Override
    public Response userInfoClaimsGeneratePost(ClaimRequestDTO properties, MessageContext messageContext) {

        if (properties != null && StringUtils.isEmpty(properties.getUsername())) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(UserInfoUtil.getError(Response.Status.BAD_REQUEST.toString(), "Bad request",
                            "username not found in the request body"))
                    .build();
        } else if (properties == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(UserInfoUtil.getError(Response.Status.BAD_REQUEST.toString(), "Bad request",
                            "Payload not found in Request body"))
                    .build();
        }
        Map<String, String> customClaims = null;
        Map<org.wso2.carbon.identity.application.common.model.ClaimMapping, String> customClaimsWithMapping =
                new HashMap<>();
        String username = properties.getUsername();
        String accessToken;
        String dialect = DEFAULT_DIALECT_URI;
        if (!StringUtils.isEmpty(properties.getAccessToken())) {
            accessToken = properties.getAccessToken();
            AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                    .getValueFromCacheByToken(new AuthorizationGrantCacheKey(accessToken));
            if (cacheEntry != null) {
                customClaimsWithMapping.putAll(cacheEntry.getUserAttributes());
            }
        }
        if (!StringUtils.isEmpty(properties.getDialect())) {
            dialect = properties.getDialect();
        }
        if (!StringUtils.isEmpty(properties.getDomain())) {
            username = UserCoreUtil.addDomainToName(username, properties.getDomain());
        }
        boolean convertDialect = false; // TODO get from the rest api payload

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String userNameWithTenantDomain = username + "@" + tenantDomain;

        try {
            customClaims = UserInfoUtil.convertClaimMap(customClaimsWithMapping, userNameWithTenantDomain, dialect,
                    convertDialect);
        } catch (Exception e) {
            log.error("Error while retrieving user claims from AuthorizationGrantCache ", e);
        }
        if (isNotEmpty(customClaims)) {
            if (log.isDebugEnabled()) {
                log.debug("The custom claims are retrieved from AuthorizationGrantCache for user : "
                        + userNameWithTenantDomain);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Custom claims are not available in the AuthorizationGrantCache. Hence will be "
                        + "retrieved from the user store for user : " + userNameWithTenantDomain);
            }
        }
        RealmService realm = (RealmService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(RealmService.class, null);
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            if (!realm.getTenantUserRealm(tenantId).getUserStoreManager().isExistingUser(username)) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(UserInfoUtil.getError(Response.Status.NOT_FOUND.toString(), "User not found",
                                "Requested user " + username + " does not exist."))
                        .build();
            }
            if (customClaims == null) {
                customClaims = new HashMap<>();
            }
            customClaims.putAll(getClaims(username, tenantId, dialect, realm));
            return Response.ok().entity(UserInfoUtil.getListDTOfromClaimsMap(customClaims)).build();
        } catch (UserStoreException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(UserInfoUtil.getError(Response.Status.INTERNAL_SERVER_ERROR.toString(),
                            "Internal server error", "Error while accessing the user store"))
                    .build();
        }
    }

    @Override
    public Response userInfoClaimsGet(String username, String domain, String dialect, MessageContext messageContext) {
        if (StringUtils.isEmpty(username)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(UserInfoUtil.getError(Response.Status.BAD_REQUEST.toString(), "Bad request",
                            "username not found in the request parameters"))
                    .build();
        }
        if (StringUtils.isEmpty(dialect)) {
            dialect = DEFAULT_DIALECT_URI;
        }
        if (!StringUtils.isEmpty(domain)) {
            username = domain + "/" + username;
        }
        RealmService realm = (RealmService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(RealmService.class, null);
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            if (!realm.getTenantUserRealm(tenantId).getUserStoreManager().isExistingUser(username)) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(UserInfoUtil.getError(Response.Status.NOT_FOUND.toString(), "User not found",
                                "Requested user " + username + " does not exist."))
                        .build();
            }
            SortedMap<String, String> claims = getClaims(username, tenantId, dialect, realm);
            return Response.ok().entity(UserInfoUtil.getListDTOfromClaimsMap(claims)).build();
        } catch (UserStoreException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(UserInfoUtil.getError(Response.Status.INTERNAL_SERVER_ERROR.toString(),
                            "Internal server error", "Error while accessing the user store"))
                    .build();
        }
    }


    private SortedMap<String, String> getClaims(String username, int tenantId, String dialectURI,
                                                UserRealmService realm) throws UserStoreException {

        SortedMap<String, String> claimValues;
        ClaimManager claimManager = realm.getTenantUserRealm(tenantId).getClaimManager();

        ClaimMapping[] claims = claimManager.getAllClaimMappings(dialectURI);

        String[] claimURIs = new String[claims.length];
        for (int i = 0; i < claims.length; i++) {
            claimURIs[i] = claims[i].getClaim().getClaimUri();
        }
        UserStoreManager userStoreManager = realm.getTenantUserRealm(tenantId).getUserStoreManager();

        claimValues = new TreeMap(userStoreManager.getUserClaimValues(username, claimURIs, null));
        if (log.isDebugEnabled()) {
            log.debug("Claims for user: " + username + " : " + claimValues.toString());
        }
        return claimValues;
    }
}
