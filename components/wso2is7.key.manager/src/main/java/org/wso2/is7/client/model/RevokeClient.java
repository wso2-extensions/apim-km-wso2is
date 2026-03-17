/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.is7.client.model;

import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.Response;
import org.wso2.carbon.apimgt.impl.kmclient.KeyManagerClientException;

/**
 * Key Manager endpoint to revoke One Time Tokens
 */
@Headers({ "Content-Type: application/x-www-form-urlencoded" })
public interface RevokeClient {

    @RequestLine("POST ")
    Response revokeToken(@Param("username") String var1, @Param("password") String var2, @Param("token") String var3,
            @Param("client_id") String var4) throws KeyManagerClientException;

}
