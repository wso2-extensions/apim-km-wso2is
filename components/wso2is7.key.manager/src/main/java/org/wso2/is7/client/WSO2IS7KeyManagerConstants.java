/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.is7.client;

/**
 * Constants related to WSO2 Identity Server 7 key manager implementation.
 */
public class WSO2IS7KeyManagerConstants {

    public static final String WSO2_IS7_TYPE = "WSO2-IS-7";
    public static final String WSO2_IS7_DISPLAY_NAME = "WSO2 Identity Server 7";
    public static final String APPLICATION_TOKEN_LIFETIME = "ext_application_token_lifetime";
    public static final String USER_TOKEN_LIFETIME = "ext_user_token_lifetime";
    public static final String REFRESH_TOKEN_LIFETIME = "ext_refresh_token_lifetime";
    public static final String ID_TOKEN_LIFETIME = "ext_id_token_lifetime";
    public static final String PKCE_MANDATORY = "ext_pkce_mandatory";
    public static final String PKCE_SUPPORT_PLAIN = "ext_pkce_support_plain";
    public static final String PUBLIC_CLIENT = "ext_public_client";
    public static final String REFRESH_TOKEN_TYPE = "Refresh";

    /**
     * Constants related to WSO2 Identity Server 7 Key Manager Connector Configuration.
     */
    public static class ConnectorConfigurationConstants {
        public static final String AUTHENTICATION = "Authentication";
        public static final String MTLS = "MutualTLS";
        public static final String BASIC_AUTH = "BasicAuth";
        public static final String USERNAME = "Username";
        public static final String PASSWORD = "Password";
        public static final String MTLS_OPTIONS = "MutualTLSOptions";
        public static final String IDENTITY_USER = "IdentityUser";
        public static final String SERVERWIDE = "ServerWide";
        public static final String TENANTWIDE = "TenantWide";
        public static final String TENANTWIDE_CERTIFICATE = "TenantWideCertificate";
        public static final String API_RESOURCE_MANAGEMENT_ENDPOINT = "api_resource_management_endpoint";
        public static final String ROLES_ENDPOINT = "is7_roles_endpoint";
        public static final String ENABLE_ROLES_CREATION = "enable_roles_creation";
    }

    /**
     * Constants related to WSO2 Identity Server 7 Tenant Sharing Configurations.
     */
    public static class IS7TenantSharingConfigs {
        public static final String ENABLE_TENANT_SYNC = "enable_tenant_sync";
        public static final String AUTO_CONFIGURE_KEY_MANAGER = "auto_configure_key_manager";
        public static final String USERNAME = "username";
        public static final String PASSWORD = "password";
        public static final String IDENTITY_SERVER_BASE_URL = "identity_server_base_url";
    }

    private WSO2IS7KeyManagerConstants() {
        // Prevents instantiation.
    }

}
