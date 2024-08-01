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

import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.apimgt.api.model.ConfigurationDto;
import org.wso2.carbon.apimgt.api.model.KeyManagerConnectorConfiguration;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.jwt.JWTValidatorImpl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Connector configuration for WSO2 Identity Server 7.
 */
@Component(
        name = "wso2is7.configuration.component",
        immediate = true,
        service = KeyManagerConnectorConfiguration.class
)
public class WSO2IS7ConnectorConfiguration implements KeyManagerConnectorConfiguration {

    @Override
    public String getImplementation() {
        return WSO2IS7KeyManager.class.getName();
    }

    @Override
    public String getJWTValidator() {
        return JWTValidatorImpl.class.getName();
    }

    @Override
    public List<ConfigurationDto> getConnectionConfigurations() {

        List<ConfigurationDto> configurationDtoList = new ArrayList<>();
        configurationDtoList
                .add(new ConfigurationDto("Username", "Username", "input", "Username of admin user", "",
                        true, false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto("Password", "Password", "input",
                        "Password of Admin user", "", true, true, Collections.emptyList(), false));

        // TODO finalize the following new ones
        configurationDtoList.add(new ConfigurationDto("api_resource_management_endpoint",
                "WSO2 Identity Server 7 API Resource Management Endpoint", "input",
                String.format("E.g., %s/api/server/v1/api-resources",
                        org.wso2.carbon.apimgt.api.APIConstants.DEFAULT_KEY_MANAGER_HOST), "", true, false,
                Collections.emptyList(), false));
        configurationDtoList.add(new ConfigurationDto("is7_roles_endpoint",
                "WSO2 Identity Server 7 Roles Endpoint", "input",
                String.format("E.g., %s/scim2/v2/Roles",
                        org.wso2.carbon.apimgt.api.APIConstants.DEFAULT_KEY_MANAGER_HOST), "", true, false,
                Collections.emptyList(), false));

        return configurationDtoList;
    }

    @Override
    public List<ConfigurationDto> getApplicationConfigurations() {

        List<ConfigurationDto> applicationConfigurationsList = new ArrayList();
        applicationConfigurationsList
                .add(new ConfigurationDto(WSO2IS7KeyManagerConstants.APPLICATION_TOKEN_LIFETIME,
                        "Lifetime of the Application Token ", "input", "Type Lifetime of the Application Token " +
                        "in seconds ", APIConstants.KeyManager.NOT_APPLICABLE_VALUE, false, false,
                        Collections.EMPTY_LIST, false));
        applicationConfigurationsList
                .add(new ConfigurationDto(WSO2IS7KeyManagerConstants.USER_TOKEN_LIFETIME,
                        "Lifetime of the User Token ", "input", "Type Lifetime of the User Token " +
                        "in seconds ", APIConstants.KeyManager.NOT_APPLICABLE_VALUE, false, false,
                        Collections.EMPTY_LIST, false));
        applicationConfigurationsList
                .add(new ConfigurationDto(WSO2IS7KeyManagerConstants.REFRESH_TOKEN_LIFETIME,
                        "Lifetime of the Refresh Token ", "input", "Type Lifetime of the Refresh Token " +
                        "in seconds ", APIConstants.KeyManager.NOT_APPLICABLE_VALUE, false, false,
                        Collections.EMPTY_LIST, false));
        applicationConfigurationsList
                .add(new ConfigurationDto(WSO2IS7KeyManagerConstants.ID_TOKEN_LIFETIME,
                        "Lifetime of the ID Token", "input", "Type Lifetime of the ID Token " +
                        "in seconds ", APIConstants.KeyManager.NOT_APPLICABLE_VALUE, false, false,
                        Collections.EMPTY_LIST, false));

        ConfigurationDto configurationDtoPkceMandatory = new ConfigurationDto(WSO2IS7KeyManagerConstants.PKCE_MANDATORY,
                "Enable PKCE", "checkbox", "Enable PKCE", String.valueOf(false), false, false,
                Collections.EMPTY_LIST, false);
        applicationConfigurationsList.add(configurationDtoPkceMandatory);

        ConfigurationDto configurationDtoPkcePlainText =
                new ConfigurationDto(WSO2IS7KeyManagerConstants.PKCE_SUPPORT_PLAIN,
                        "Support PKCE Plain text", "checkbox", "S256 is recommended, plain text too can be used.",
                        String.valueOf(false), false, false, Collections.EMPTY_LIST, false);
        applicationConfigurationsList.add(configurationDtoPkcePlainText);

        ConfigurationDto configurationDtoBypassClientCredentials =
                new ConfigurationDto(WSO2IS7KeyManagerConstants.PUBLIC_CLIENT,
                        "Public client", "checkbox", "Allow authentication without the client secret.",
                        String.valueOf(false), false, false, Collections.EMPTY_LIST, false);
        applicationConfigurationsList.add(configurationDtoBypassClientCredentials);

        return applicationConfigurationsList;
    }

    @Override
    public String getType() {

        return WSO2IS7KeyManagerConstants.WSO2_IS7_TYPE;
    }

    @Override
    public String getDisplayName() {

        return WSO2IS7KeyManagerConstants.WSO2_IS7_DISPLAY_NAME;
    }

    @Override
    public String getDefaultScopesClaim() {

        return APIConstants.JwtTokenConstants.SCOPE;
    }

    @Override
    public String getDefaultConsumerKeyClaim() {

        return APIConstants.JwtTokenConstants.AUTHORIZED_PARTY;
    }

}
