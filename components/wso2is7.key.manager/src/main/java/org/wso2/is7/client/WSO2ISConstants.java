/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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
 * This class will hold constants related to WSO2IS key manager implementation.
 */
public class WSO2ISConstants {

    public static final String WSO2IS_TYPE = "WSO2-IS";
    public static final String DISPLAY_NAME = "WSO2 Identity Server";
    public static final String KEY_MANAGER_USERNAME = "Username";
    public static final String OAUTH_CLIENT_USERNAME = "username";
    public static final String KM_ADMIN_AS_APP_OWNER_NAME = "km_admin_as_app_owner";
    public static final String KM_ADMIN_AS_APP_OWNER_LABEL =
            "Enable admin user as the owner of created OAuth applications";
    public static final String KM_ADMIN_AS_APP_OWNER_VALUE = "Use as OAuth Application Owner";
    public static final String SCIM2_CORE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0";
    public static final String SCIM2_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
    public static final String SCIM2_ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    public static final String SCIM2_SYSTEM_SCHEMA_URI = "urn:scim:wso2:schema";
    public static final String SCIM2_CUSTOM_SCHEMA_URI = "urn:scim:schemas:extension:custom:User";
    public static final String MULTIVALUED_ATTRIBUTE_SEPARATOR = ",";
    public static final String USER_SCHEMA_CACHE = "userSchemaCache";
    public static final String ENABLE_SCHEMA_CACHE = "user_schema_cache_enabled";

    // Attribute Schema Related Constants
    public static final String CASE_EXACT =  "caseExact";
    public static final String MULTI_VALUED = "multiValued";
    public static final String REQUIRED = "required";
    public static final String MUTABILITY = "mutability";
    public static final String RETURNED = "returned";
    public static final String UNIQUENESS = "uniqueness";
    public static final String CANONICAL_VALUES = "canonicalValues";
    public static final String REFERENCE_TYPES = "referenceTypes";

    WSO2ISConstants() {

    }
}
