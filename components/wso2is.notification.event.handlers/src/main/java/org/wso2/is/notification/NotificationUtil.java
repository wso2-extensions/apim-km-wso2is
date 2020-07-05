
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

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static org.wso2.is.notification.NotificationConstants.HEADER_PROPERTY;

/**
 * Utility class for Notifications
 */
public class NotificationUtil {

    private NotificationUtil() {

    }

    public static Map<String, String> extractHeadersMapFromProperties(Properties properties) {

        Map<String, String> headers = new HashMap<>();
        for (Map.Entry<Object, Object> propertiesEntry : properties.entrySet()) {
            String key = (String) propertiesEntry.getKey();
            String value = (String) propertiesEntry.getValue();
            if (key.startsWith(HEADER_PROPERTY)) {
                headers.put(key.split(HEADER_PROPERTY)[1], value);
            }
        }
        return headers;
    }
}
