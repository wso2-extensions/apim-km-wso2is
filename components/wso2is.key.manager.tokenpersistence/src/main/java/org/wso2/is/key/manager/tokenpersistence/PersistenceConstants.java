/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com)
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.is.key.manager.tokenpersistence;

/**
 * Constants related to persistence component.
 */
public class PersistenceConstants {
    public static final String REFRESH_TOKEN = "refresh_token";

    /**
     * Constants for JWT Claims.
     */
    public static class JWTClaim {

        public static final String AUDIENCE = "aud";
        public static final String CLIENT_ID = "client_id";
        public static final String SCOPE = "scope";
        public static final String AUTHORIZATION_PARTY = "azp";
        public static final String IS_CONSENTED = "is_consented";
        public static final String TOKEN_TYPE_ELEM = "token_type";
    }
    public static final int SECONDS_TO_MILISECONDS_FACTOR = 1000;
    public static final String PREV_ACCESS_TOKEN = "previousAccessToken";

}
