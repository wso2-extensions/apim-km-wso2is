/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.is.key.manager.core.tokenmgt.handlers;

/***
 * Constants for resources in token mgt
 */
public final class ResourceConstants {

    public static final String CHECK_ROLES_FROM_SAML_ASSERTION = "checkRolesFromSamlAssertion";
    public static final String SAML2_ASSERTION = "SAML2Assertion";
    public static final String SAML2_SSO_AUTHENTICATOR_NAME = "SAML2SSOAuthenticator";
    public static final String ROLE_CLAIM_ATTRIBUTE = "RoleClaimAttribute";
    public static final String ATTRIBUTE_VALUE_SEPARATOR = "AttributeValueSeparator";
    public static final String ROLE_ATTRIBUTE_NAME = "http://wso2.org/claims/role";
    public static final String ATTRIBUTE_VALUE_SEPERATER = ",";
    public static final String
            RETRIEVE_ROLES_FROM_USERSTORE_FOR_SCOPE_VALIDATION = "retrieveRolesFromUserStoreForScopeValidation";
    public static final String ROLE_CLAIM = "ROLE_CLAIM";
    public static final String OAUTH2_DEFAULT_SCOPE = "default";
    public static final String REST_API_SCOPE_CACHE = "REST_API_SCOPE_CACHE";
    public static final String EXTENTIONS_CACHE_MANAGER = "EXTENTIONS_CACHE_MANAGER";
    public static final String TENANT_CONFIG_CACHE_NAME = "tenantConfigCache";
    public static final String REST_API_SCOPE = "Scope";
    public static final String REST_API_SCOPE_NAME = "Name";
    public static final String REST_API_SCOPE_ROLE = "Roles";
    public static final String REST_API_SCOPES_CONFIG = "RESTAPIScopes";
    public static final String REST_API_ROLE_MAPPINGS_CONFIG = "RoleMappings";
    public static final String GROUPS = "groups";

    //governance registry apimgt root location
    public static final String APIMGT_REGISTRY_LOCATION = "/apimgt";
    public static final String API_APPLICATION_DATA_LOCATION = APIMGT_REGISTRY_LOCATION + "/applicationdata";
    public static final String API_TENANT_CONF = "tenant-conf.json";
    public static final String API_TENANT_CONF_LOCATION = API_APPLICATION_DATA_LOCATION + "/" + API_TENANT_CONF;

    /**
     * Constants for correlation logging
     * */
    public static final String CORRELATION_ID = "Correlation-ID";
    public static final String ENABLE_CORRELATION_LOGS = "enableCorrelationLogs";
    public static final String CORRELATION_LOGGER = "correlation";
    public static final String LOG_ALL_METHODS = "logAllMethods";
    public static final String AM_ACTIVITY_ID = "activityid";

}
