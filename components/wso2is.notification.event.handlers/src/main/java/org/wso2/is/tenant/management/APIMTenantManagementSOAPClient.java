package org.wso2.is.tenant.management;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.wso2.carbon.tenant.mgt.stub.TenantMgtAdminServiceExceptionException;
import org.wso2.carbon.tenant.mgt.stub.TenantMgtAdminServiceStub;
import org.wso2.carbon.tenant.mgt.stub.beans.xsd.TenantInfoBean;

import java.rmi.RemoteException;

/**
 * SOAP Client for Managing Tenants in API Manager side
 */
public class APIMTenantManagementSOAPClient {
    private static final String TENANT_MANAGEMENT_ADMIN_SERVICE = "TenantMgtAdminService";

    public static void createTenantInAPIM(org.wso2.carbon.stratos.common.beans.TenantInfoBean tenant,
                                          String reservedUserName, String reservedUserPassword)
            throws RemoteException, TenantMgtAdminServiceExceptionException {
        String backendURL = "https://localhost:9443/services/";

        TenantMgtAdminServiceStub stub = new TenantMgtAdminServiceStub(backendURL + TENANT_MANAGEMENT_ADMIN_SERVICE);

        // Authenticate stub
        ServiceClient client = stub._getServiceClient();
        Options options = client.getOptions();
        HttpTransportProperties.Authenticator auth = new HttpTransportProperties.Authenticator();
        auth.setUsername(reservedUserName);
        auth.setPassword(reservedUserPassword);
        auth.setPreemptiveAuthentication(true);
        options.setProperty(org.apache.axis2.transport.http.HTTPConstants.AUTHENTICATE, auth);

        // Build tenant DTO
        TenantInfoBean tenantInfoBean = new TenantInfoBean();
        tenantInfoBean.setTenantDomain(tenant.getTenantDomain());
        tenantInfoBean.setAdmin(tenant.getAdmin());
        tenantInfoBean.setAdminPassword(tenant.getAdminPassword());
        tenantInfoBean.setEmail(tenant.getEmail());
        tenantInfoBean.setFirstname(tenant.getFirstname());
        tenantInfoBean.setLastname(tenant.getLastname());
        tenantInfoBean.setActive(true);

        // Call APIM
        stub.addTenant(tenantInfoBean);
    }

    public static void updateTenantInAPIM(org.wso2.carbon.stratos.common.beans.TenantInfoBean tenant,
                                          String reservedUserName, String reservedUserPassword)
            throws RemoteException, TenantMgtAdminServiceExceptionException {
        String backendURL = "https://localhost:9443/services/";

        TenantMgtAdminServiceStub stub = new TenantMgtAdminServiceStub(backendURL + TENANT_MANAGEMENT_ADMIN_SERVICE);

        // Authenticate stub
        ServiceClient client = stub._getServiceClient();
        Options options = client.getOptions();
        HttpTransportProperties.Authenticator auth = new HttpTransportProperties.Authenticator();
        auth.setUsername(reservedUserName);
        auth.setPassword(reservedUserPassword);
        auth.setPreemptiveAuthentication(true);
        options.setProperty(org.apache.axis2.transport.http.HTTPConstants.AUTHENTICATE, auth);

        //Since it checks for the tenant ID in tenantInfoBean, to access UserRegistry in APIM side
        TenantInfoBean tenantInfoInAPIM = stub.getTenant(tenant.getTenantDomain());

        // Build tenant DTO
        TenantInfoBean tenantInfoBean = new TenantInfoBean();
        tenantInfoBean.setTenantId(tenantInfoInAPIM.getTenantId());
        tenantInfoBean.setTenantDomain(tenant.getTenantDomain());
        tenantInfoBean.setAdmin(tenant.getAdmin());
        tenantInfoBean.setAdminPassword(tenant.getAdminPassword());
        tenantInfoBean.setEmail(tenant.getEmail());
        tenantInfoBean.setFirstname(tenant.getFirstname());
        tenantInfoBean.setLastname(tenant.getLastname());
        tenantInfoBean.setActive(tenant.isActive());
        tenantInfoBean.setCreatedDate(tenant.getCreatedDate());

        // Call APIM
        stub.updateTenant(tenantInfoBean);
    }

    public static void activateTenantInAPIM(String tenantDomain, String reservedUserName, String reservedUserPassword)
            throws RemoteException, TenantMgtAdminServiceExceptionException {
        String backendURL = "https://localhost:9443/services/";

        TenantMgtAdminServiceStub stub = new TenantMgtAdminServiceStub(backendURL + TENANT_MANAGEMENT_ADMIN_SERVICE);

        // Authenticate stub
        ServiceClient client = stub._getServiceClient();
        Options options = client.getOptions();
        HttpTransportProperties.Authenticator auth = new HttpTransportProperties.Authenticator();
        auth.setUsername(reservedUserName);
        auth.setPassword(reservedUserPassword);
        auth.setPreemptiveAuthentication(true);
        options.setProperty(org.apache.axis2.transport.http.HTTPConstants.AUTHENTICATE, auth);

        stub.activateTenant(tenantDomain);
    }

    public static void deactivateTenantInAPIM(String tenantDomain, String reservedUserName, String reservedUserPassword)
            throws RemoteException, TenantMgtAdminServiceExceptionException {
        String backendURL = "https://localhost:9443/services/";

        TenantMgtAdminServiceStub stub = new TenantMgtAdminServiceStub(backendURL + TENANT_MANAGEMENT_ADMIN_SERVICE);

        // Authenticate stub
        ServiceClient client = stub._getServiceClient();
        Options options = client.getOptions();
        HttpTransportProperties.Authenticator auth = new HttpTransportProperties.Authenticator();
        auth.setUsername(reservedUserName);
        auth.setPassword(reservedUserPassword);
        auth.setPreemptiveAuthentication(true);
        options.setProperty(org.apache.axis2.transport.http.HTTPConstants.AUTHENTICATE, auth);

        stub.deactivateTenant(tenantDomain);
    }
}
