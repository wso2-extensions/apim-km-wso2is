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
 *
 */

package org.wso2.is.key.manager.core.tokenmgt.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.is.key.manager.core.tokenmgt.issuers.AbstractScopesIssuer;

import java.util.HashMap;
import java.util.Map;

/**
 * TokenMgt data holder to keep track on osgi Services
 */
public class TokenMgtDataHolder {

    private static RegistryService registryService;
    private static RealmService realmService;
    private static Boolean isKeyCacheEnabledKeyMgt = true;
    private static Map<String, AbstractScopesIssuer> scopesIssuers = new HashMap<String, AbstractScopesIssuer>();
    private static final Log log = LogFactory.getLog(TokenMgtDataHolder.class);


    public static Boolean getKeyCacheEnabledKeyMgt() {
        return isKeyCacheEnabledKeyMgt;
    }

    public static void setKeyCacheEnabledKeyMgt(Boolean keyCacheEnabledKeyMgt) {
        isKeyCacheEnabledKeyMgt = keyCacheEnabledKeyMgt;
    }

    public static RegistryService getRegistryService() {
        return registryService;
    }

    public static void setRegistryService(RegistryService registryService) {
        TokenMgtDataHolder.registryService = registryService;
    }


    /**
     * Add scope issuers to the map.
     * @param prefix prefix of the scope issuer.
     * @param scopesIssuer scope issuer instance.
     */
    public static void addScopesIssuer(String prefix, AbstractScopesIssuer scopesIssuer) {
        scopesIssuers.put(prefix, scopesIssuer);
    }

    public static void setScopesIssuers(Map<String, AbstractScopesIssuer> scpIssuers) {
        scopesIssuers = scpIssuers;
    }

    public static Map<String, AbstractScopesIssuer> getScopesIssuers() {
        return scopesIssuers;
    }
}
