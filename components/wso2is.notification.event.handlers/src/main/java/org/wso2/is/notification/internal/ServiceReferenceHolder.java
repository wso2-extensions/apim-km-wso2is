package org.wso2.is.notification.internal;

import org.wso2.carbon.user.core.service.RealmService;

/**
 * Holder class to hold service references used in notification.
 */
public class ServiceReferenceHolder {

    private static final ServiceReferenceHolder instance = new ServiceReferenceHolder();
    private RealmService realmService;

    public static ServiceReferenceHolder getInstance() {

        return instance;
    }

    private ServiceReferenceHolder() {

    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public RealmService getRealmService() {

        return realmService;
    }
}
