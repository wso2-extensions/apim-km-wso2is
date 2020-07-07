
/*
 *   Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.is.notification;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.config.RealmConfigXMLProcessor;
import org.wso2.is.notification.internal.ServiceReferenceHolder;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static org.wso2.is.notification.NotificationConstants.ENVIRONMENT_VARIABLE_ENDING_CHAR;
import static org.wso2.is.notification.NotificationConstants.ENVIRONMENT_VARIABLE_STARTING_CHAR;
import static org.wso2.is.notification.NotificationConstants.HEADER_PROPERTY;

/**
 * Utility class for Notifications
 */
public class NotificationUtil {

    private static final Log log = LogFactory.getLog(NotificationUtil.class);

    private NotificationUtil() {

    }

    public static Map<String, String> extractHeadersMapFromProperties(Properties properties) {

        Map<String, String> headers = new HashMap<>();
        for (Map.Entry<Object, Object> propertiesEntry : properties.entrySet()) {
            String key = (String) propertiesEntry.getKey();
            String value = (String) propertiesEntry.getValue();
            if (key.startsWith(HEADER_PROPERTY)) {
                headers.put(key.split(HEADER_PROPERTY)[1], replaceSystemProperty(value));
            }
        }
        return headers;
    }

    /**
     * Resolves system properties and replaces in given in text
     *
     * @param text
     * @return System properties resolved text
     */
    public static String replaceSystemProperty(String text) {

        int indexOfStartingChars = -1;
        int indexOfClosingBrace;

        // The following condition deals with properties.
        // Properties are specified as ${system.property},
        // and are assumed to be System properties
        while (indexOfStartingChars < text.indexOf(ENVIRONMENT_VARIABLE_STARTING_CHAR)
                && (indexOfStartingChars = text.indexOf(ENVIRONMENT_VARIABLE_STARTING_CHAR)) != -1
                && (indexOfClosingBrace = text.indexOf(ENVIRONMENT_VARIABLE_ENDING_CHAR)) != -1) { // Is a
            // property
            // used?
            String sysProp = text.substring(indexOfStartingChars + 2,
                    indexOfClosingBrace);
            String propValue = System.getProperty(sysProp);

            if (propValue == null) {
                if (NotificationConstants.CARBON_CONTEXT.equals(sysProp)) {
                    propValue = ServiceReferenceHolder.getInstance().getContextService().getServerConfigContext()
                            .getContextRoot();
                } else if (NotificationConstants.ADMIN_USER_NAME_SYSTEM_PROPERTY.equals(sysProp) ||
                        NotificationConstants.ADMIN_PASSWORD_SYSTEM_PROPERTY.equals(sysProp)) {
                    try {
                        RealmConfiguration realmConfig =
                                new RealmConfigXMLProcessor().buildRealmConfigurationFromFile();
                        if (NotificationConstants.ADMIN_USER_NAME_SYSTEM_PROPERTY.equals(sysProp)) {
                            propValue = realmConfig.getAdminUserName();
                        } else {
                            propValue = realmConfig.getAdminPassword();
                        }
                    } catch (UserStoreException e) {
                        // Can't throw an exception because the server is
                        // starting and can't be halted.
                        log.error("Unable to build the Realm Configuration", e);
                        return null;
                    }
                }
            }
            //Derive original text value with resolved system property value
            if (propValue != null) {
                text = text.substring(0, indexOfStartingChars) + propValue
                        + text.substring(indexOfClosingBrace + 1);
            }
            if (NotificationConstants.CARBON_HOME_SYSTEM_PROPERTY.equals(sysProp) && ".".equals(propValue)) {
                text = new File(".").getAbsolutePath() + File.separator + text;
            }
        }
        return text;
    }

}
