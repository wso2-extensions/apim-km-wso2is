/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.is.key.manager.core.observers;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.AbstractAxis2ConfigurationContextObserver;
import org.wso2.is.key.manager.core.internal.ServiceReferenceHolder;

import java.util.HashMap;
import java.util.Random;

/**
 * Observer class for keeping track of tenant loading/unloading operations
 */
public class ReservedUserCreationObserver extends AbstractAxis2ConfigurationContextObserver
        implements org.wso2.carbon.core.ServerStartupObserver {

    private static final Log log = LogFactory.getLog(ReservedUserCreationObserver.class);
    private static final String DEFAULT_RESERVED_USERNAME = "apim_reserved_user";
    private static final String EVERYONE_ROLE = "internal/everyone";

    public void createdConfigurationContext(ConfigurationContext configurationContext) {
        createReservedUser();
    }

    /**
     * Creates a reserved user to be used in cross tenant subscription scenarios, so that the tenant admin is
     * not exposed in JWT tokens generated. This logic will be run to add this user to the tenants if it
     * is not existing. This value can be changed from a config as well.
     */
    public void createReservedUser() {
        try {
            RealmService realmService = ServiceReferenceHolder.getInstance().getRealmService();
            int tenantId = getTenantId();
            if (realmService != null && tenantId != MultitenantConstants.INVALID_TENANT_ID) {
                UserStoreManager userStoreManager =
                        (UserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
                if (userStoreManager.isReadOnly()) {
                    log.warn("Unable to create the reserved user. Please create a user by" +
                            " the name: " + DEFAULT_RESERVED_USERNAME + " in the user store.");
                    return;
                }
                boolean isReservedUserCreated = userStoreManager.isExistingUser(DEFAULT_RESERVED_USERNAME);
                if (!isReservedUserCreated) {
                    userStoreManager.addUser(DEFAULT_RESERVED_USERNAME, getSaltString(),
                            new String[]{EVERYONE_ROLE},
                            new HashMap<>(), DEFAULT_RESERVED_USERNAME, false);
                }
            }
        } catch (UserStoreException e) {
            log.error("Error occurred while getting the realm configuration, User store properties might not be " +
                    "returned", e);
        }
    }

    /**
     * Retrieves the tenant id from the Thread Local Carbon Context
     *
     * @return tenant id
     */
    int getTenantId() {
        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
    }

    public void terminatingConfigurationContext(ConfigurationContext configContext) {
        // do nothing
    }

    @Override
    public void completingServerStartup() {

    }

    @Override
    public void completedServerStartup() {
        createReservedUser();
    }

    /**
     * Generates random password for the reserved user
     * @return the random string value generated
     */
    private String getSaltString() {
        String saltChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        StringBuilder salt = new StringBuilder();
        Random rnd = new Random();
        while (salt.length() < 18) {
            int index = (int) (rnd.nextFloat() * saltChars.length());
            salt.append(saltChars.charAt(index));
        }
        return salt.toString();
    }
}