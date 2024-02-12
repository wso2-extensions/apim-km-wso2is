/*
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.is.notification.event;

import org.wso2.is.notification.NotificationConstants;

import java.util.UUID;

/**
 * Internal Consumer App Revocation Event Model.
 */
public class ConsumerAppRevocationEvent extends Event {
    private static final long serialVersionUID = 1L;

    private String consumerKey;
    private long revocationTime;

    public ConsumerAppRevocationEvent(String consumerKey) {

        this.eventId = UUID.randomUUID().toString();
        this.timeStamp = System.currentTimeMillis();
        this.type = NotificationConstants.CONSUMER_APP_REVOCATION_EVENT;
        this.consumerKey = consumerKey;
    }

    public String getConsumerKey() {
        return consumerKey;
    }

    public void setConsumerKey(String consumerKey) {

        this.consumerKey = consumerKey;
    }

    public long getRevocationTime() {
        return revocationTime;
    }

    public void setRevocationTime(long revocationTime) {
        this.revocationTime = revocationTime;
    }

    @Override
    public String toString() {

        return "ConsumerAppRevocationEvent{" +
                "eventId='" + eventId + '\'' +
                ", type='" + type + '\'' +
                ", consumerKey='" + consumerKey + '\'' +
                ", revocationTime=" + revocationTime + '\'' +
                ", tenantDomain='" + tenantDomain + '\'' +
                '}';
    }
}
