/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.wso2.is.key.manager.core.handlers;

import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.registry.core.jdbc.handlers.Handler;
import org.wso2.carbon.registry.core.jdbc.handlers.RequestContext;
import org.wso2.is.key.manager.core.tokenmgt.handlers.ResourceConstants;
import org.wso2.is.key.manager.core.tokenmgt.util.CacheProvider;

import javax.cache.Cache;

/**
 * Handler class to clear the extensions caches when tenant-config is updated
 */
public class TenantConfigMediaTypeHandler extends Handler {

    public void put(RequestContext requestContext) {
        clearConfigCache();
    }

    public void delete(RequestContext requestContext) {
        clearConfigCache();
    }

    private void clearConfigCache() {
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String cacheKey = tenantId + "_" + ResourceConstants.TENANT_CONFIG_CACHE_NAME;
        boolean tenantFlowStarted = false;

        if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            try {
                PrivilegedCarbonContext.startTenantFlow();
                tenantFlowStarted = true;
                PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
                carbonContext.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                carbonContext.setTenantId(MultitenantConstants.SUPER_TENANT_ID);
                // Clear the necessary caches of the extensions
                clearExtensionsManagerCaches(cacheKey, tenantDomain);
            } finally {
                if (tenantFlowStarted) {
                    PrivilegedCarbonContext.endTenantFlow();
                }
            }
        } else {
            // Clear the necessary caches of the extensions
            clearExtensionsManagerCaches(cacheKey, tenantDomain);
        }
    }

    private void clearExtensionsManagerCaches(String cacheKey, String tenantDomain) {
        // Clear the tenant-config cache of the extensions
        Cache tenantConfigCache = CacheProvider.getInstance().getTenantConfigCache();
        tenantConfigCache.remove(cacheKey);

        // Clear the REST API Scope cache of the extensions
        Cache restApiScopesCache = CacheProvider.getInstance().getRESTAPIScopeCache();
        restApiScopesCache.remove(tenantDomain);
    }
}
