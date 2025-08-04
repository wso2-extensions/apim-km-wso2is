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

import feign.Headers;
import feign.Param;
import feign.RequestLine;
import org.wso2.carbon.stratos.common.exception.StratosException;

import java.util.List;


/**
 * Represents the WSO2 Identity Server 7 Tenant Management API
 */

public interface WSO2IS7TenantManagementClient {

    @RequestLine("POST /tenants")
    @Headers("Content-Type: application/json")
    String createTenant(TenantInfo tenantInfo) throws StratosException;

    @RequestLine("GET /tenants/domain/{tenant-domain}")
    @Headers("Content-Type: application/json")
    TenantResponse getTenantByDomain(@Param("tenant-domain") String tenantDomain) throws StratosException;

    @RequestLine("GET /tenants/{tenant-id}/owners")
    @Headers("Content-Type: application/json")
    List<TenantOwnerResponse> getTenantOwners(@Param("tenant-id") String tenantId)
            throws StratosException;

    @RequestLine("PUT /tenants/{tenant-id}/owners/{owner-id}")
    @Headers("Content-Type: application/json")
    void updateTenantOwner(@Param("tenant-id") String tenantId, @Param("owner-id") String ownerId,
                                 TenantOwnerUpdateInfo tenantOwner) throws StratosException;

    @RequestLine("PUT /tenants/{tenant-id}/lifecycle-status")
    @Headers("Content-Type: application/json")
    String updateTenantStatus(@Param("tenant-id") String tenantId, TenantStatusUpdateInfo tenantStatusUpdateInfo)
            throws StratosException;

}
