/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.is7.client.utils;

import feign.auth.BasicAuthRequestInterceptor;

import java.nio.charset.StandardCharsets;

/**
 * Creates the Basic authentication request interceptors used by the WSO2 IS7 connector's Feign clients.
 * <p>
 * The credentials are encoded as UTF-8, which is how WSO2 IS 7 decodes them. Feign's
 * {@link BasicAuthRequestInterceptor#BasicAuthRequestInterceptor(String, String)} constructor encodes them as
 * ISO-8859-1, so WSO2 IS 7 rejects credentials with non-ASCII characters. ASCII credentials are encoded to the same
 * bytes in both charsets.
 */
public final class BasicAuthInterceptorUtil {

    private BasicAuthInterceptorUtil() {

    }

    /**
     * Creates a Basic authentication request interceptor which encodes the given credentials as UTF-8.
     *
     * @param username username
     * @param password password
     * @return Basic authentication request interceptor
     */
    public static BasicAuthRequestInterceptor createBasicAuthInterceptor(String username, String password) {

        return new BasicAuthRequestInterceptor(username, password, StandardCharsets.UTF_8);
    }
}
