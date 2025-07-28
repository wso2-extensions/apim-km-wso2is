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
 * Represents the tenant creation request payload for WSO2 Identity Server 7.
 * From Here : https://github.com/wso2/identity-api-server/blob/master/
 * components/org.wso2.carbon.identity.api.server.tenant.management/
 * org.wso2.carbon.identity.api.server.tenant.management.v1/src/gen/java/org/wso2/carbon/identity/api/server/tenant/
 * management/v1/model/TenantInfo.java
 */
public class TenantInfo {

    public TenantInfo() {}

    @SerializedName("domain")
    private String domain;

    @SerializedName("name")
    private String name;

    @SerializedName("owners")
    private List<TenantOwnerInfo> owners;


    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }

    public List<TenantOwnerInfo> getOwners() {
        return owners;
    }

    public void setOwners(List<TenantOwnerInfo> owners) {
        this.owners = owners;
    }

}
