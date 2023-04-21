/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.is.notification;

import org.apache.commons.lang.*;
import org.apache.commons.logging.*;
import org.wso2.carbon.identity.oauth.common.exception.*;
import org.wso2.carbon.user.api.*;
import org.wso2.is.notification.event.*;

import java.util.*;
import java.util.Properties;

public class InternalTokenRevocationInterceptor extends ApimOauthEventInterceptor {

    String notificationEndpoint;
    Map<String, String> headerMap = new HashMap<>();
    boolean enabled;
    String username;
    char[] password;
    private EventSender eventSender;
    private static final String JWT = "JWT";

    public InternalTokenRevocationInterceptor() {
        super.init(initConfig);
        String endpointProperty = properties.getProperty(NotificationConstants.NOTIFICATION_ENDPOINT);
        String usernameProperty = properties.getProperty(NotificationConstants.USERNAME);
        String passwordProperty = properties.getProperty(NotificationConstants.PASSWORD);
        if (StringUtils.isNotEmpty(endpointProperty)) {
            enabled = true;
            notificationEndpoint = NotificationUtil.replaceSystemProperty(endpointProperty);
            headerMap.putAll(NotificationUtil.extractHeadersMapFromProperties(properties));
            if (StringUtils.isNotEmpty(usernameProperty) && StringUtils.isNotEmpty(passwordProperty)) {
                username = NotificationUtil.replaceSystemProperty(usernameProperty);
                password = NotificationUtil.replaceSystemProperty(passwordProperty).toCharArray();
                eventSender = new EventSender(notificationEndpoint, username, String.valueOf(password), headerMap);
            } else {
                eventSender = new EventSender(notificationEndpoint, headerMap);
            }
        }
    }

    public void publishEvent(InternalTokenRevocationEvent internalTokenRevocationEvent) {
        if (isEnabled()) {
            if (StringUtils.isNotEmpty(notificationEndpoint)) {
                eventSender.publishEvent(internalTokenRevocationEvent);
            }
        }
    }
}
