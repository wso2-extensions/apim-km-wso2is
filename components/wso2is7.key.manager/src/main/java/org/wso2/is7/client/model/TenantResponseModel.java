/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com)
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

package org.wso2.is7.client.model;
import com.google.gson.annotations.SerializedName;

import java.util.List;

/**
 * Represents the tenant response model for WSO2 Identity Server 7.
**/
public class TenantResponseModel  {

    @SerializedName("id")
    private String id;

    @SerializedName("name")
    private String name;

    @SerializedName("domain")
    private String domain;

    @SerializedName("owners")
    private List<OwnerResponse> owners = null;

    @SerializedName("createdDate")
    private String createdDate;

    @SerializedName("lifecycleStatus")
    private LifeCycleStatus lifecycleStatus;

    @SerializedName("region")
    private String region;

    public String getId() {
        return id;
    }
    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }

    public String getDomain() {
        return domain;
    }
    public void setDomain(String domain) {
        this.domain = domain;
    }

    public List<OwnerResponse> getOwners() {
        return owners;
    }
    public void setOwners(List<OwnerResponse> owners) {
        this.owners = owners;
    }


    public String getCreatedDate() {
        return createdDate;
    }
    public void setCreatedDate(String createdDate) {
        this.createdDate = createdDate;
    }

    public LifeCycleStatus getLifecycleStatus() {
        return lifecycleStatus;
    }
    public void setLifecycleStatus(LifeCycleStatus lifecycleStatus) {
        this.lifecycleStatus = lifecycleStatus;
    }

    public String getRegion() {
        return region;
    }
    public void setRegion(String region) {
        this.region = region;
    }

    /**
     * Represents an owner of a tenant.
     */
    public static class OwnerResponse  {
        private String id;
        private String username;
        public String getId() {
            return id;
        }
        public void setId(String id) {
            this.id = id;
        }
        public String getUsername() {
            return username;
        }
        public void setUsername(String username) {
            this.username = username;
        }
    }

    /**
     * Represents the lifecycle status of a tenant.
     */
    public static class LifeCycleStatus  {
        private Boolean activated;

        public Boolean getActivated() {
            return activated;
        }
        public void setActivated(Boolean activated) {
            this.activated = activated;
        }
    }
}

