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
package org.wso2.is.client;

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
    public static final String ENABLE_APPLICATION_SCOPE_NAME = "enable_application_scopes";
    public static final String ENABLE_APPLICATION_SCOPE_LABEL = "Enable application scopes for Oauth applications";
    public static final String ENABLE_APPLICATION_SCOPE_VALUE = "Enable Application Scopes";

    WSO2ISConstants() {

    }
}
