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
import java.util.Map;

/**
 * Represents the client information returned from WSO2 Identity Server 7.
 */
public class WSO2IS7RoleInfo {

    public WSO2IS7RoleInfo() {}

    @SerializedName("id")
    private String id;

    @SerializedName("displayName")
    private String displayName;

    @SerializedName("schemas")
    private List<String> schemas;

    @SerializedName("permissions")
    private List<Map<String, String>> permissions;

    @SerializedName("audience")
    private Map<String, String> audience;

    @SerializedName("meta")
    private Map<String, String> meta;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public List<String> getSchemas() {
        return schemas;
    }

    public void setSchemas(List<String> schemas) {
        this.schemas = schemas;
    }

    public List<Map<String, String>> getPermissions() {
        return permissions;
    }

    public void setPermissions(List<Map<String, String>> permissions) {
        this.permissions = permissions;
    }

    public Map<String, String> getAudience() {
        return audience;
    }

    public void setAudience(Map<String, String> audience) {
        this.audience = audience;
    }

    public Map<String, String> getMeta() {
        return meta;
    }

    public void setMeta(Map<String, String> meta) {
        this.meta = meta;
    }
}
