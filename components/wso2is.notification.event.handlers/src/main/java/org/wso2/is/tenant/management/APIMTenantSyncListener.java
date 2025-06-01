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
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.is.tenant.management.internal.ServiceReferenceHolder;

import java.rmi.RemoteException;
import java.util.Map;

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
        UserRealm userRealm = null;
        try {
            Tenant tenant = realmService.getTenantManager().getTenant(tenantInfoBean.getTenantId());
            String organizationID = tenant.getAssociatedOrganizationUUID();

            // check if the Organization Depth in the Hierarchy is -1. only then create the root org.
            if (organizationID == null ||
                    getOrganizationManager().getOrganizationDepthInHierarchy(organizationID) == -1) {

                userRealm = realmService.getTenantUserRealm(tenantInfoBean.getTenantId());

                UserStoreManager userStoreManager = userRealm.getUserStoreManager();

                Map<String, String> claimValues = userStoreManager.getUserClaimValues(
                        tenantInfoBean.getAdmin(),
                        new String[]{
                                "http://wso2.org/claims/givenname",
                                "http://wso2.org/claims/lastname"
                        },
                        null
                );

                String firstName = claimValues.get("http://wso2.org/claims/givenname");
                String lastName = claimValues.get("http://wso2.org/claims/lastname");

                log.info("Tenant admin first name: " + firstName);
                tenantInfoBean.setFirstname(firstName);

                log.info("Tenant admin last name: " + lastName);
                tenantInfoBean.setLastname(lastName);

                APIMTenantManagementSOAPClient.createTenantInAPIM(tenantInfoBean);
            } else {
                log.info("Triggered Event is not related to a root org creation");
            }

        //if there was an exception thrown here, tenant activation won't happen
        } catch (UserStoreException | OrganizationManagementServerException e) {
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
    public void onTenantActivation(int i) throws StratosException {

    }

    @Override
    public void onTenantDeactivation(int i) throws StratosException {

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
