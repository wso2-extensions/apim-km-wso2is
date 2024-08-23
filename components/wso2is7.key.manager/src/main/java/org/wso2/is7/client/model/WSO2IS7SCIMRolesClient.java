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

import com.google.gson.JsonObject;
import feign.Headers;
import feign.Param;
import feign.RequestLine;
import org.wso2.carbon.apimgt.impl.kmclient.KeyManagerClientException;

/**
 * Represents the WSO2 Identity Server SCIM2 Roles client.
 */
public interface WSO2IS7SCIMRolesClient {

    @RequestLine("GET /{roleId}")
    @Headers("Content-Type: application/json")
    WSO2IS7RoleInfo getRole(@Param("roleId") String roleId) throws KeyManagerClientException;

    @RequestLine("POST ")
    @Headers("Content-Type: application/json")
    WSO2IS7RoleInfo createRole(WSO2IS7RoleInfo role) throws KeyManagerClientException;

    @RequestLine("POST /.search")
    @Headers("Content-Type: application/json")
    JsonObject searchRoles(JsonObject payload) throws KeyManagerClientException;

    @RequestLine("PATCH /{roleId}")
    @Headers("Content-Type: application/json")
    void patchRole(@Param("roleId") String roleId, WSO2IS7PatchRoleOperationInfo patchRoleOperationInfo)
            throws KeyManagerClientException;

}