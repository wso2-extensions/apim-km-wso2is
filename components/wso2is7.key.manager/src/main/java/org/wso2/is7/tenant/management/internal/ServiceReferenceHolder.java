package org.wso2.is7.tenant.management.internal;

import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.service.TenantRegistryLoader;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

/**
 * Holder class to hold service references used in notification.
 */
public class ServiceReferenceHolder {

    private static final ServiceReferenceHolder instance = new ServiceReferenceHolder();
    private RealmService realmService;
    private RegistryService registryService;
    private TenantRegistryLoader tenantRegistryLoader;
    private ConfigurationContextService contextService;
    private OrganizationManager organizationManager;

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

    public ConfigurationContextService getContextService() {
        return contextService;
    }

    public void setContextService(ConfigurationContextService contextService) {
        this.contextService = contextService;
    }

    public OrganizationManager getOrganizationManager() {
        return organizationManager;
    }

    public void setOrganizationManager(OrganizationManager organizationManager) {
        this.organizationManager = organizationManager;
    }

}
