/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
    private boolean isRevokeAppOnly;
    private long revocationTime;
    private String revocationType;

    public InternalTokenRevocationConsumerKeyEvent(String consumerKey, boolean isRevokeAppOnly, Properties properties) {

        this.eventId = UUID.randomUUID().toString();
        this.timeStamp = System.currentTimeMillis();
        this.type = NotificationConstants.INTERNAL_TOKEN_REVOCATION_CONSUMER_KEY_EVENT;
        this.consumerKey = consumerKey;
        this.isRevokeAppOnly = isRevokeAppOnly;
        this.revocationTime = (long) properties.get("revocationTime");

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

    public String getRevocationType() {
        return revocationType;
    }

    public void setRevocationType(String revocationType) {
        this.revocationType = revocationType;
    }

    public boolean isRevokeAppOnly() {
        return isRevokeAppOnly;
    }

    public void setRevokeAppOnly(boolean revokeAppOnly) {
        isRevokeAppOnly = revokeAppOnly;
    }

    @Override
    public String toString() {

        return "TokenRevocationEvent{" +
                "eventId='" + eventId + '\'' +
                ", type='" + type + '\'' +
                ", consumerKey='" + consumerKey + '\'' +
                ", isRevokeAppOnly=" + isRevokeAppOnly + '\'' +
                ", revocationTime=" + revocationTime + '\'' +
                ", revocationType=" + revocationType + '\'' +
                ", tenantDomain='" + tenantDomain + '\'' +
                '}';
    }
}
