package org.wso2.is.notification.internal;

import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.is.notification.NotificationEventSenderService;

/**
 * Holder class to hold service references used in notification.
 */
public class ServiceReferenceHolder {

    private static final ServiceReferenceHolder instance = new ServiceReferenceHolder();
    private RealmService realmService;
    private ConfigurationContextService contextService;
    private NotificationEventSenderService eventSender;

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

    public NotificationEventSenderService getEventSender() {
        return eventSender;
    }

    public void setEventSender(NotificationEventSenderService eventSender) {
        this.eventSender = eventSender;
    }
}
