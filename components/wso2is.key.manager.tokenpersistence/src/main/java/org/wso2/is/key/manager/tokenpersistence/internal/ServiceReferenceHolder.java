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

package org.wso2.is.key.manager.tokenpersistence.internal;

import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAOImpl;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.is.key.manager.tokenpersistence.dao.DBInvalidTokenPersistence;
import org.wso2.is.key.manager.tokenpersistence.model.InvalidTokenPersistenceService;

/**
 * Holder class to hold service references used in non-token persistence.
 */
public class ServiceReferenceHolder {
    private static final ServiceReferenceHolder instance = new ServiceReferenceHolder();
    private RealmService realmService;
    private InvalidTokenPersistenceService tokenPersistenceService;
    private AccessTokenDAO migratedAccessTokenDAO;

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

    public synchronized InvalidTokenPersistenceService getInvalidTokenPersistenceService() {

        if (tokenPersistenceService == null) {
            tokenPersistenceService = DBInvalidTokenPersistence.getInstance();
        }
        return tokenPersistenceService;
    }

    public synchronized void setInvalidTokenPersistenceService(
            InvalidTokenPersistenceService invalidTokenPersistenceService) {

        tokenPersistenceService = invalidTokenPersistenceService;
    }

    public AccessTokenDAO getMigratedAccessTokenDAO() {

        if (migratedAccessTokenDAO == null) {
            migratedAccessTokenDAO = new AccessTokenDAOImpl();
        }
        return migratedAccessTokenDAO;
    }

    public void setMigratedAccessTokenDAO(AccessTokenDAO migratedAccessTokenDAO) {

        this.migratedAccessTokenDAO = migratedAccessTokenDAO;
    }
}
