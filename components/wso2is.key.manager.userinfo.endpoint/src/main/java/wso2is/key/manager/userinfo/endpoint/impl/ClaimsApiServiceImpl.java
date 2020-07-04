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

package wso2is.key.manager.userinfo.endpoint.impl;

import wso2is.key.manager.userinfo.endpoint.*;
import wso2is.key.manager.userinfo.endpoint.dto.*;

import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.user.api.ClaimManager;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.UserRealmService;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.MessageContext;

import wso2is.key.manager.userinfo.endpoint.dto.ClaimListDTO;
import wso2is.key.manager.userinfo.endpoint.dto.ClaimRequestDTO;
import wso2is.key.manager.userinfo.endpoint.dto.ErrorDTO;
import wso2is.key.manager.userinfo.endpoint.util.UserInfoUtil;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.io.InputStream;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;


public class ClaimsApiServiceImpl implements ClaimsApiService {

    private static final Log log = LogFactory.getLog(ClaimsApiServiceImpl.class);
    private final String DEFAULT_DIALECT_URI = "http://wso2.org/claims";
    public Response claimsGeneratePost(ClaimRequestDTO properties, MessageContext messageContext) {
        if(properties != null && StringUtils.isEmpty(properties.getUsername())) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(UserInfoUtil.getError(Response.Status.BAD_REQUEST.toString(), "Bad request",
                            "username not found in the request body"))
                    .build();
        }
        Map<String, String> customClaims;
        String username = properties.getUsername();
        String accessToken = null;
        String dialect = DEFAULT_DIALECT_URI;
        if (properties != null) {
            if (!StringUtils.isEmpty(properties.getAccessToken())) {
                accessToken = properties.getAccessToken();
            }
            if (!StringUtils.isEmpty(properties.getDialect())) {
                dialect = properties.getDialect();
            }
            if (!StringUtils.isEmpty(properties.getDomain())) {
                username = properties.getDomain() + "/" + username;
            }
        }
        //TODO load claims using AuthorizationGrantCache
        customClaims = new HashMap<String, String>();
        
        RealmService realm = (RealmService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(RealmService.class, null);
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            if(!realm.getTenantUserRealm(tenantId).getUserStoreManager().isExistingUser(username)) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(UserInfoUtil.getError(Response.Status.NOT_FOUND.toString(), "User not found",
                                "Requested user " + username + " does not exist."))
                        .build();
            }
            customClaims.putAll(getClaims(username, tenantId , dialect, realm));;
            return Response.ok().entity(UserInfoUtil.getListDTOfromClaimsMap(customClaims)).build();
        } catch (UserStoreException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(UserInfoUtil.getError(Response.Status.INTERNAL_SERVER_ERROR.toString(),
                            "Internal server error", "Error while accessing the user store"))
                    .build();
        }
    }

    public Response claimsGet(String username, String domain, String dialect, MessageContext messageContext) {
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
        if(log.isDebugEnabled()) {
            log.debug("Claims for user: " + username + " : " + claimValues.toString());
        }
        return claimValues;
    }
}
