package org.wso2.is.tenant.management;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementServerException;
import org.wso2.carbon.stratos.common.beans.TenantInfoBean;
import org.wso2.carbon.stratos.common.exception.StratosException;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;
import org.wso2.carbon.tenant.mgt.internal.TenantMgtServiceComponent;
import org.wso2.carbon.tenant.mgt.stub.TenantMgtAdminServiceExceptionException;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.is.tenant.management.internal.ServiceReferenceHolder;

import java.rmi.RemoteException;

/**
 * Listener class for Tenant management in IS
 */
public class APIMTenantSyncListener implements TenantMgtListener {
    private static final Log log = LogFactory.getLog(APIMTenantSyncListener.class);

    @Override
    public void onTenantCreate(TenantInfoBean tenantInfoBean) throws StratosException {
        String tenantDomain = tenantInfoBean.getTenantDomain();
        log.info("Tenant created in IS: " + tenantDomain);

        // Wait until the tenant flow is started
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        carbonContext.setTenantId(tenantInfoBean.getTenantId());
        carbonContext.setTenantDomain(tenantDomain);

        RealmService realmService = TenantMgtServiceComponent.getRealmService();

        try {
            Tenant tenant = realmService.getTenantManager().getTenant(tenantInfoBean.getTenantId());
            String organizationID = tenant.getAssociatedOrganizationUUID();

            // check if the Organization Depth in the Hierarchy is -1. only then create the root org.
            if (organizationID == null ||
                    getOrganizationManager().getOrganizationDepthInHierarchy(organizationID) == -1) {

                APIMTenantManagementSOAPClient.createTenantInAPIM(tenantInfoBean);
            } else {
                log.info("Skipping creating the tenant in APIM since the triggered Event is not related " +
                        "to a root org creation.");
            }

        //if there was an exception thrown here, tenant activation won't happen
        } catch (UserStoreException | OrganizationManagementServerException e) {
            log.error(e.getMessage(), e);
            throw new StratosException(e.getMessage());
        } catch (RemoteException | TenantMgtAdminServiceExceptionException e) {
            String errorMessage = "Error while syncing tenant to APIM";
            log.error(errorMessage, e);
            throw new StratosException(errorMessage);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Override
    public void onTenantUpdate(TenantInfoBean tenantInfoBean) throws StratosException {
        String tenantDomain = tenantInfoBean.getTenantDomain();
        log.info("Tenant updated in IS: " + tenantDomain);

        // Wait until the tenant flow is started
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        carbonContext.setTenantId(tenantInfoBean.getTenantId());
        carbonContext.setTenantDomain(tenantDomain);

        RealmService realmService = TenantMgtServiceComponent.getRealmService();

        try {
            Tenant tenant = realmService.getTenantManager().getTenant(tenantInfoBean.getTenantId());
            String organizationID = tenant.getAssociatedOrganizationUUID();

            // check if the Organization Depth in the Hierarchy is -1. only then create the root org.
            if (organizationID == null ||
                    getOrganizationManager().getOrganizationDepthInHierarchy(organizationID) == 0) {

                APIMTenantManagementSOAPClient.updateTenantInAPIM(tenantInfoBean);
            } else {
                log.info("Skipping updating the tenant in APIM since the triggered Event is not related " +
                        "to a root org update.");
            }

            //if there was an exception thrown here, tenant activation won't happen
        } catch (UserStoreException | OrganizationManagementServerException e) {
            log.error(e.getMessage(), e);
            throw new StratosException(e.getMessage());
        } catch (RemoteException | TenantMgtAdminServiceExceptionException e) {
            String errorMessage = "Error while syncing tenant to APIM";
            log.error(errorMessage, e);
            throw new StratosException(errorMessage);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Override
    public void onTenantDelete(int i) {

    }

    @Override
    public void onTenantRename(int i, String s, String s1) throws StratosException {

    }

    @Override
    public void onTenantInitialActivation(int i) throws StratosException {

    }

    @Override
    public void onTenantActivation(int tenantID) throws StratosException {
        log.info("Tenant activated in IS: " + tenantID);

        // Wait until the tenant flow is started
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        carbonContext.setTenantId(tenantID);

        RealmService realmService = TenantMgtServiceComponent.getRealmService();

        try {
            Tenant tenant = realmService.getTenantManager().getTenant(tenantID);
            String organizationID = tenant.getAssociatedOrganizationUUID();

            // check if the Organization Depth in the Hierarchy is -1. only then create the root org.
            if (organizationID == null ||
                    getOrganizationManager().getOrganizationDepthInHierarchy(organizationID) == 0) {

                APIMTenantManagementSOAPClient.activateTenantInAPIM(tenant.getDomain());
            } else {
                log.info("Skipping activation of the tenant in APIM since the triggered Event is not related " +
                        "to a root org.");
            }

            //if there was an exception thrown here, tenant activation won't happen
        } catch (UserStoreException | OrganizationManagementServerException e) {
            log.error(e.getMessage(), e);
            throw new StratosException(e.getMessage());
        } catch (RemoteException | TenantMgtAdminServiceExceptionException e) {
            String errorMessage = "Error while syncing tenant to APIM";
            log.error(errorMessage, e);
            throw new StratosException(errorMessage);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Override
    public void onTenantDeactivation(int tenantID) throws StratosException {
        log.info("Tenant activated in IS: " + tenantID);

        // Wait until the tenant flow is started
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        carbonContext.setTenantId(tenantID);

        RealmService realmService = TenantMgtServiceComponent.getRealmService();

        try {
            Tenant tenant = realmService.getTenantManager().getTenant(tenantID);
            String organizationID = tenant.getAssociatedOrganizationUUID();

            // check if the Organization Depth in the Hierarchy is -1. only then create the root org.
            if (organizationID == null ||
                    getOrganizationManager().getOrganizationDepthInHierarchy(organizationID) == 0) {

                APIMTenantManagementSOAPClient.deactivateTenantInAPIM(tenant.getDomain());
            } else {
                log.info("Skipping deactivation of the tenant in APIM since the triggered Event is not related " +
                        "to a root org.");
            }
            //if there was an exception thrown here, tenant activation won't happen
        } catch (UserStoreException | OrganizationManagementServerException e) {
            log.error(e.getMessage(), e);
            throw new StratosException(e.getMessage());
        } catch (RemoteException | TenantMgtAdminServiceExceptionException e) {
            String errorMessage = "Error while syncing tenant to APIM";
            log.error(errorMessage, e);
            throw new StratosException(errorMessage);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Override
    public void onSubscriptionPlanChange(int i, String s, String s1) throws StratosException {

    }

    @Override
    public int getListenerOrder() {
        return 0;
    }

    @Override
    public void onPreDelete(int i) throws StratosException {

    }

    @Override
    public void onPreTenantCreate(TenantInfoBean tenantInfoBean) throws StratosException {
        TenantMgtListener.super.onPreTenantCreate(tenantInfoBean);
    }

    @Override
    public void onPostDelete(int tenantId, String tenantUuid, String adminUserUuid) throws StratosException {
        TenantMgtListener.super.onPostDelete(tenantId, tenantUuid, adminUserUuid);
    }

    private OrganizationManager getOrganizationManager() {

        return ServiceReferenceHolder.getInstance().getOrganizationManager();
    }

}
