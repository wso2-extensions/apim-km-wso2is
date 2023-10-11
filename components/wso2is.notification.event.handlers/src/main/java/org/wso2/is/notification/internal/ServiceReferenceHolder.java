package org.wso2.is.notification.internal;

import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.is.notification.EventSender;

/**
 * Holder class to hold service references used in notification.
 */
public class ServiceReferenceHolder {

    private static final ServiceReferenceHolder instance = new ServiceReferenceHolder();
    private RealmService realmService;
    private ConfigurationContextService contextService;
    private EventSender eventSender;

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
    public ConfigurationContextService getContextService() {
        return contextService;
    }

    public void setContextService(ConfigurationContextService contextService) {
        this.contextService = contextService;
    }

    public EventSender getEventSender() {
        return eventSender;
    }

    public void setEventSender(EventSender eventSender) {
        this.eventSender = eventSender;
    }
}
