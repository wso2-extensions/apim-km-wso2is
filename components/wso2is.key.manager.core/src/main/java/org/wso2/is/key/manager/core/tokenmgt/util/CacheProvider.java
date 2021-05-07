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

package org.wso2.is.key.manager.core.tokenmgt.util;

import org.wso2.is.key.manager.core.tokenmgt.handlers.ResourceConstants;

import javax.cache.Cache;
import javax.cache.Caching;

/**
 * Class for initiating and returning caches. Creating cache take place when super tenant loading and tenant loading
 */
public class CacheProvider {

    private static final CacheProvider instance = new CacheProvider();

    private CacheProvider() {
    }

    /**
     * Method to get the instance of the CacheProvider.
     *
     * @return {@link CacheProvider} instance
     */
    public static CacheProvider getInstance() {
        return instance;
    }

    /**
     * @return Tenant Config cache
     */
    public static Cache getTenantConfigCache() {
        return getCache(ResourceConstants.TENANT_CONFIG_CACHE_NAME);
    }

    /**
     * @return Product REST API scope cache
     */
    public static Cache getRESTAPIScopeCache() {
        return getCache(ResourceConstants.REST_API_SCOPE_CACHE);
    }

    /**
     * @param cacheName name of the requested cache
     * @return cache
     */
    private static Cache getCache(final String cacheName) {
        return Caching.getCacheManager(ResourceConstants.EXTENTIONS_CACHE_MANAGER).getCache(cacheName);
    }

}
