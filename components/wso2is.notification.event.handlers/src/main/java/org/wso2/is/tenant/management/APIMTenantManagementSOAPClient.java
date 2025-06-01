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

    public static void createTenantInAPIM(org.wso2.carbon.stratos.common.beans.TenantInfoBean tenant)
            throws RemoteException, TenantMgtAdminServiceExceptionException {
        String backendURL = "https://localhost:9443/services/";
        String username = "tenantmgt";
        String password = "admin123";

        TenantMgtAdminServiceStub stub = new TenantMgtAdminServiceStub(backendURL + TENANT_MANAGEMENT_ADMIN_SERVICE);

        // Authenticate stub
        ServiceClient client = stub._getServiceClient();
        Options options = client.getOptions();
        HttpTransportProperties.Authenticator auth = new HttpTransportProperties.Authenticator();
        auth.setUsername(username);
        auth.setPassword(password);
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

    public static void activateTenantInAPIM(String tenantDomain)
            throws RemoteException, TenantMgtAdminServiceExceptionException {
        String backendURL = "https://localhost:9443/services/";
        String username = "admin";
        String password = "admin";

        TenantMgtAdminServiceStub stub = new TenantMgtAdminServiceStub(backendURL + TENANT_MANAGEMENT_ADMIN_SERVICE);

        // Authenticate stub
        ServiceClient client = stub._getServiceClient();
        Options options = client.getOptions();
        HttpTransportProperties.Authenticator auth = new HttpTransportProperties.Authenticator();
        auth.setUsername(username);
        auth.setPassword(password);
        auth.setPreemptiveAuthentication(true);
        options.setProperty(org.apache.axis2.transport.http.HTTPConstants.AUTHENTICATE, auth);

        stub.activateTenant(tenantDomain);
    }

    public static void deactivateTenantInAPIM(String tenantDomain)
            throws RemoteException, TenantMgtAdminServiceExceptionException {
        String backendURL = "https://localhost:9443/services/";
        String username = "admin";
        String password = "admin";

        TenantMgtAdminServiceStub stub = new TenantMgtAdminServiceStub(backendURL + TENANT_MANAGEMENT_ADMIN_SERVICE);

        // Authenticate stub
        ServiceClient client = stub._getServiceClient();
        Options options = client.getOptions();
        HttpTransportProperties.Authenticator auth = new HttpTransportProperties.Authenticator();
        auth.setUsername(username);
        auth.setPassword(password);
        auth.setPreemptiveAuthentication(true);
        options.setProperty(org.apache.axis2.transport.http.HTTPConstants.AUTHENTICATE, auth);

        stub.deactivateTenant(tenantDomain);
    }
}
