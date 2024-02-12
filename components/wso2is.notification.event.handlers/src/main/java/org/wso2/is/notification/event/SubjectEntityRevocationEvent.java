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
 * Subject Entity Revocation Event Model.
 */
public class SubjectEntityRevocationEvent extends Event {
    private static final long serialVersionUID = 1L;

    private String entityId;
    private String entityType;
    private long revocationTime;

    public SubjectEntityRevocationEvent(String entityId, String entityType) {

        this.eventId = UUID.randomUUID().toString();
        this.timeStamp = System.currentTimeMillis();
        this.type = NotificationConstants.SUBJECT_ENTITY_REVOCATION_EVENT;
        this.entityId = entityId;
        this.entityType = entityType;
    }

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

    public String getEntityType() {
        return entityType;
    }

    public void setEntityType(String entityType) {
        this.entityType = entityType;
    }

    public long getRevocationTime() {
        return revocationTime;
    }

    public void setRevocationTime(long revocationTime) {
        this.revocationTime = revocationTime;
    }


    @Override
    public String toString() {

        return "SubjectEntityRevocationEvent{" +
                ", eventId='" + eventId + '\'' +
                ", tenantId=" + tenantId + '\'' +
                ", timeStamp=" + timeStamp + '\'' +
                ", tenantDomain='" + tenantDomain + '\'' +
                ", type='" + type + '\'' +
                ", entityId='" + entityId + '\'' +
                ", entityType='" + entityType + '\'' +
                ", revocationTime=" + revocationTime + '\'' +
                '}';
    }
}
