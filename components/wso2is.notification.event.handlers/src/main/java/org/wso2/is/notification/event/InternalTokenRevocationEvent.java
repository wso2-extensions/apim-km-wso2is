
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

package org.wso2.is.notification.event;

import org.wso2.is.notification.*;

import java.util.*;

/**
 * Token Revocation Event Model to send Event.
 */
public class InternalTokenRevocationEvent extends Event {
    private static final long serialVersionUID = 1L;

    private String revocationTime;
    private String consumerKey;
    private String revocationType;

    public InternalTokenRevocationEvent(String consumerKey, Properties properties) {

        this.eventId = UUID.randomUUID().toString();
        this.type = NotificationConstants.INTERNAL_TOKEN_REVOCATION_EVENT;
        this.consumerKey = consumerKey;
        this.revocationTime = String.valueOf(System.currentTimeMillis());
        this.revocationType = (String) properties.getProperty("action");

    }

    public String getConsumerKey() {
        return consumerKey;
    }
    public void setConsumerKey(String consumerKey) {

        this.consumerKey = consumerKey;
    }

    public String getRevocationTime() {
        return revocationTime;
    }

    public void setRevocationTime(String revocationTime) {
        this.revocationTime = revocationTime;
    }

    public String getRevocationType() {
        return revocationType;
    }

    public void setRevocationType(String revocationType) {
        this.revocationType = revocationType;
    }

    @Override
    public String toString() {

        return "TokenRevocationEvent{" +
                "eventId='" + eventId + '\'' +
                ", type='" + type + '\'' +
                ", consumerKey='" + consumerKey + '\'' +
                ", revocationTime=" + revocationTime +
                ", revocationType=" + revocationType +
                ", tenantId=" + tenantId +
                ", tenantDomain='" + tenantDomain + '\'' +
                '}';
    }
}
