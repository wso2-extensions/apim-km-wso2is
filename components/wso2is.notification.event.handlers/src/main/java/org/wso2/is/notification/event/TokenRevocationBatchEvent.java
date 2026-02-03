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
package org.wso2.is.notification.event;

import org.wso2.is.notification.NotificationConstants;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Token Revocation Event Model to send Event.
 */
public class TokenRevocationBatchEvent extends Event {
    private static final long serialVersionUID = 1L;

    private String consumerKey;
    private List<TokenRevocationEvent> tokenRevocationEventList;

    public TokenRevocationBatchEvent(String consumerKey) {
        this.eventId = UUID.randomUUID().toString();
        this.timeStamp = System.currentTimeMillis();
        this.type = NotificationConstants.TOKEN_REVOCATION_BATCH_EVENT;
        this.consumerKey = consumerKey;
        this.tokenRevocationEventList = new ArrayList<>();
    }

    public List<TokenRevocationEvent> getTokenRevocationEventList() {
        return tokenRevocationEventList;
    }

    public void setTokenRevocationEventList(List<TokenRevocationEvent> tokenRevocationEventList) {
        this.tokenRevocationEventList = tokenRevocationEventList;
    }

    public void addTokenRevocationEventToList(TokenRevocationEvent tokenRevocationEvent) {
        this.tokenRevocationEventList.add(tokenRevocationEvent);
    }

    public String getConsumerKey() {
        return consumerKey;
    }
    public void setConsumerKey(String consumerKey) {
        this.consumerKey = consumerKey;
    }

    @Override
    public String toString() {

        return "TokenRevocationBatchEvent{" +
                ", eventId='" + eventId + '\'' +
                ", timeStamp=" + timeStamp +
                ", type='" + type + '\'' +
                ", tenantId=" + tenantId +
                ", tenantDomain='" + tenantDomain + '\'' +
                ", consumerKey='" + consumerKey + '\'' +
                ", tokenRevocationEventList='" + tokenRevocationEventList + '\'' +
                '}';
    }
}
