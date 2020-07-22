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
 * /
 */

package org.wso2.is.key.manager.core.handlers;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.handler.impl.BasicAuthenticationHandler;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.is.key.manager.core.internal.ServiceReferenceHolder;

/**
 * This class handles the Basic authentication and User
 */
public class ExtendedISAuthHandler extends BasicAuthenticationHandler {

    private static final Log log = LogFactory.getLog(ExtendedISAuthHandler.class);
    private static final String BASIC_AUTH_HEADER = "Basic";
    private static final String X_WSO2_TENANT_HEADER = "X-WSO2-Tenant";

    public ExtendedISAuthHandler() {

        super();
    }

    @Override
    public void init(InitConfig initConfig) {

        super.init(initConfig);
    }

    @Override
    public String getName() {

        return "ExtendedISAuthHandler";
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        return super.getPriority(messageContext) - 1;
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {

        boolean authHeaderMatch = AuthConfigurationUtil.isAuthHeaderMatch(messageContext, BASIC_AUTH_HEADER);
        return authHeaderMatch && StringUtils.isNotEmpty(getHeader(messageContext, X_WSO2_TENANT_HEADER));
    }

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext) throws AuthenticationFailException {

        AuthenticationResult authenticationResult = super.doAuthenticate(messageContext);
        if (AuthenticationStatus.SUCCESS.equals(authenticationResult.getAuthenticationStatus())) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            String tenantHeader = getHeader(messageContext, X_WSO2_TENANT_HEADER);
            String effectiveTenant = null;
            boolean superAdmin = false;
            if (authenticationContext.getUser() != null) {
                User user = authenticationContext.getUser();
                try {
                    RealmService realmService = ServiceReferenceHolder.getInstance().getRealmService();
                    TenantManager tenantManager = realmService.getTenantManager();

                    // Check user was admin of super tenant
                    if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(user.getTenantDomain())) {
                        UserRealm superTenantUserRealm =
                                realmService.getTenantUserRealm(MultitenantConstants.SUPER_TENANT_ID);
                        String superAdminUserName = superTenantUserRealm.getRealmConfiguration().getAdminUserName();
                        if (superAdminUserName.equals(user.getUserName())) {
                            superAdmin = true;
                        }
                    }

                    if (StringUtils.isNotEmpty(tenantHeader)) {
                        if (superAdmin) {
                            effectiveTenant = tenantHeader.trim();
                        } else {
                            authenticationResult.setAuthenticationStatus(AuthenticationStatus.FAILED);
                            return authenticationResult;
                        }
                    }
                    if (StringUtils.isNotEmpty(effectiveTenant)) {
                        int tenantId = tenantManager.getTenantId(effectiveTenant);
                        Tenant tenant = tenantManager.getTenant(tenantId);
                        if (tenant != null) {
                            if (!tenant.isActive()) {
                                authenticationResult.setAuthenticationStatus(AuthenticationStatus.FAILED);
                                return authenticationResult;
                            } else {
                                user.setTenantDomain(tenant.getDomain());
                                user.setUserName(tenant.getAdminName());
                            }
                        } else {
                            authenticationResult.setAuthenticationStatus(AuthenticationStatus.FAILED);
                            return authenticationResult;
                        }
                    }
                } catch (UserStoreException e) {
                    String errorMessage = "Error occurred while trying to authenticate. " + e.getMessage();
                    log.error(errorMessage);
                    throw new AuthenticationFailException(errorMessage);
                }
            }
        }
        return authenticationResult;
    }

    private String getHeader(MessageContext messageContext, String header) {

        if (messageContext instanceof AuthenticationContext) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            if (authenticationContext.getAuthenticationRequest() != null) {
                AuthenticationRequest authenticationRequest = authenticationContext.getAuthenticationRequest();
                return authenticationRequest.getHeader(header);
            }
        }
        return null;
    }
}
