/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
 * Represents the client information returned from WSO2 Identity Server 7.
 */
public class WSO2IS7APIResourceInfo {

    public WSO2IS7APIResourceInfo() {}

    @SerializedName("id")
    private String id;

    @SerializedName("name")
    private String name;

    @SerializedName("description")
    private String description;
    @SerializedName("identifier")
    private String identifier;

    @SerializedName("type")
    private String type;

    @SerializedName("requiresAuthorization")
    private boolean requiresAuthorization;

    @SerializedName("scopes")
    private List<WSO2IS7APIResourceScopeInfo> scopes;


    // TODO Properties? do we need, and can we survive without this


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

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public boolean isRequiresAuthorization() {
        return requiresAuthorization;
    }

    public void setRequiresAuthorization(boolean requiresAuthorization) {
        this.requiresAuthorization = requiresAuthorization;
    }

    public List<WSO2IS7APIResourceScopeInfo> getScopes() {
        return scopes;
    }

    public void setScopes(List<WSO2IS7APIResourceScopeInfo> scopes) {
        this.scopes = scopes;
    }
}
