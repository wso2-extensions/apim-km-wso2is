/*
 *   Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com)
 *
 *   WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.is.notification.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.is.notification.EventSender;
import org.wso2.is.notification.NotificationConstants;
import org.wso2.is.notification.NotificationEventSenderService;
import org.wso2.is.notification.NotificationUtil;
import org.wso2.is.notification.event.Event;

import java.util.Map;
import java.util.Properties;

/**
 * Implementation of NotificationEventSenderService.
 */
public class NotificationEventSenderServiceImpl implements NotificationEventSenderService {

    private static final Log log = LogFactory.getLog(NotificationEventSenderServiceImpl.class);
    private EventSender eventSender;
    private boolean enabled;

    public NotificationEventSenderServiceImpl(Properties properties) {

        String endpointProperty = properties.getProperty(NotificationConstants.NOTIFICATION_ENDPOINT);
        String usernameProperty = properties.getProperty(NotificationConstants.USERNAME);
        String passwordProperty = properties.getProperty(NotificationConstants.PASSWORD);

        if (StringUtils.isNotEmpty(endpointProperty)) {
            enabled = true;
            String notificationEndpoint = NotificationUtil.replaceSystemProperty(endpointProperty);
            Map<String, String> headerMap = NotificationUtil.extractHeadersMapFromProperties(properties);

            if (StringUtils.isNotEmpty(usernameProperty) && StringUtils.isNotEmpty(passwordProperty)) {
                String username = NotificationUtil.replaceSystemProperty(usernameProperty);
                String password = NotificationUtil.replaceSystemProperty(passwordProperty);
                eventSender = new EventSender(notificationEndpoint, username, password, headerMap);
            } else {
                eventSender = new EventSender(notificationEndpoint, headerMap);
            }
        }
    }

    @Override
    public void publishEvent(Event event) {

        if (enabled && eventSender != null) {
            eventSender.publishEvent(event);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Event sender is not enabled or configured. Skipping event publishing.");
            }
        }
    }

}
