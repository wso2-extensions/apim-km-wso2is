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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import feign.Headers;
import feign.Param;
import feign.QueryMap;
import feign.RequestLine;
import org.wso2.carbon.apimgt.impl.kmclient.KeyManagerClientException;

import java.util.Map;

/**
 * Represents the WSO2 Identity Server 7 API Resource Management client.
 */
public interface WSO2IS7APIResourceManagementClient {

    @RequestLine("POST ")
    @Headers("Content-Type: application/json")
    WSO2IS7APIResourceInfo createAPIResource(WSO2IS7APIResourceInfo apiResourceInfo) throws KeyManagerClientException;

    @RequestLine("GET ?{parameters}")
    @Headers("Content-Type: application/json")
    JsonObject getAPIResources(@QueryMap Map<String, String> parameters) throws KeyManagerClientException;

    @RequestLine("GET /{apiResourceId}/scopes")
    @Headers("Content-Type: application/json")
    JsonArray getAPIResourceScopes(@Param("apiResourceId") String apiResourceId) throws KeyManagerClientException;

    @RequestLine("PATCH /{apiResourceId}")
    @Headers("Content-Type: application/json")
    void patchAPIResource(@Param("apiResourceId") String apiResourceId, JsonObject payload)
            throws KeyManagerClientException;

    @RequestLine("PATCH /{apiResourceId}/scopes/{scopeName}")
    @Headers("Content-Type: application/json")
    void patchAPIResourceScope(@Param("apiResourceId") String apiResourceId, @Param("scopeName") String scopeName,
                               JsonObject payload) throws KeyManagerClientException;

    @RequestLine("DELETE /{apiResourceId}/scopes/{scopeName}")
    @Headers("Content-Type: application/json")
    void deleteScopeFromAPIResource(@Param("apiResourceId") String apiResourceId, @Param("scopeName") String scopeName)
            throws KeyManagerClientException;

}
