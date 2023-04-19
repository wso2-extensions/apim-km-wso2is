/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.is.key.manager.tokenpersistence.internal;

import org.wso2.carbon.identity.oauth2.*;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.service.TenantRegistryLoader;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.is.key.manager.tokenpersistence.dao.*;
import org.wso2.is.key.manager.tokenpersistence.model.InvalidTokenPersistenceService;

/**
 * Service holder to keep track on osgi Services
 */
public class ServiceReferenceHolder {
    private static final Object lock = new Object();
    private static final ServiceReferenceHolder instance = new ServiceReferenceHolder();
    private RealmService realmService;
    private RegistryService registryService;
    private TenantRegistryLoader tenantRegistryLoader;
    private static ConfigurationContextService contextService;
    private static InvalidTokenPersistenceService tokenPersistenceService;
    private static InternalRevocationEventService internalRevocationEventService;

    private ServiceReferenceHolder() {
        
    }
    public static ServiceReferenceHolder getInstance() {

        return instance;
    }
    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public RegistryService getRegistryService() {
        return registryService;
    }

    public void setRegistryService(RegistryService registryService) {
        this.registryService = registryService;
    }

    public TenantRegistryLoader getTenantRegistryLoader() {
        return tenantRegistryLoader;
    }

    public void setTenantRegistryLoader(TenantRegistryLoader tenantRegistryLoader) {
        this.tenantRegistryLoader = tenantRegistryLoader;
    }

    public static ConfigurationContextService getContextService() {
        return contextService;
    }

    public static void setContextService(ConfigurationContextService contextService) {
        ServiceReferenceHolder.contextService = contextService;
    }

    public static synchronized InvalidTokenPersistenceService getInvalidTokenPersistenceService() {
        if (tokenPersistenceService == null) {
            tokenPersistenceService = DBInvalidTokenPersistence.getInstance();     
        }
        return tokenPersistenceService;
    }
    
    public static void setInvalidTokenPersistenceService(
            InvalidTokenPersistenceService invalidTokenPersistenceService) {
        tokenPersistenceService = invalidTokenPersistenceService;
    }

    public static synchronized InternalRevocationEventService getInternalRevocationEventService() {
        if (internalRevocationEventService == null) {
            internalRevocationEventService = DBInternalRevocationEventService.getInstance();
        }
        return internalRevocationEventService;
    }

    public static void setInternalRevocationEventService(
            InternalRevocationEventService revocationEventService) {
        internalRevocationEventService = revocationEventService;
    }

}
