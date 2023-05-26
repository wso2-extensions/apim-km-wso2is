/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
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

import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.apimgt.api.model.ConfigurationDto;
import org.wso2.carbon.apimgt.api.model.KeyManagerConnectorConfiguration;
import org.wso2.carbon.apimgt.impl.DefaultKeyManagerConnectorConfiguration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Connector configuration for WSO2IS.
 */
@Component(
        name = "wso2is.configuration.component",
        immediate = true,
        service = KeyManagerConnectorConfiguration.class
)
public class WSO2ISConnectorConfiguration extends DefaultKeyManagerConnectorConfiguration {

    @Override
    public String getImplementation() {

        return WSO2ISOAuthClient.class.getName();
    }

    @Override
    public String getJWTValidator() {

        return null;
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
        configurationDtoList.add(new ConfigurationDto("km_admin_as_app_owner",
                "Enable admin user as the owner of created OAuth applications", "select",
                "Enable admin user as the owner of created OAuth applications", "", false, false,
                Collections.singletonList("Use as Application Owner"), false));
        configurationDtoList.addAll(super.getConnectionConfigurations());
        return configurationDtoList;
    }

    @Override
    public List<ConfigurationDto> getApplicationConfigurations() {

        return super.getApplicationConfigurations();
    }

    @Override
    public String getType() {

        return WSO2ISConstants.WSO2IS_TYPE;
    }

    @Override
    public String getDisplayName() {

        return WSO2ISConstants.DISPLAY_NAME;
    }
}
