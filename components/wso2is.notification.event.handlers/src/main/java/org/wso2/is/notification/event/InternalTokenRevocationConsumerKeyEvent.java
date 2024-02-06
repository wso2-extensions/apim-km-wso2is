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

import java.util.Properties;
import java.util.UUID;

/**
 * Internal Token Revocation Consumer Key Event Model
 */
public class InternalTokenRevocationConsumerKeyEvent extends Event {
    private static final long serialVersionUID = 1L;

    private String consumerKey;
    private long revocationTime;
    private String organization;

    public InternalTokenRevocationConsumerKeyEvent(String consumerKey, Properties properties) {

        this.eventId = UUID.randomUUID().toString();
        this.timeStamp = System.currentTimeMillis();
        this.type = NotificationConstants.INTERNAL_TOKEN_REVOCATION_CONSUMER_KEY_EVENT;
        this.consumerKey = consumerKey;
        this.revocationTime = (long) properties.get("revocationTime");
        this.organization = properties.get("organization").toString();

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

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    @Override
    public String toString() {

        return "TokenRevocationEvent{" +
                "eventId='" + eventId + '\'' +
                ", type='" + type + '\'' +
                ", consumerKey='" + consumerKey + '\'' +
                ", revocationTime=" + revocationTime + '\'' +
                ", organization=" + organization + '\'' +
                ", tenantDomain='" + tenantDomain + '\'' +
                '}';
    }
}
