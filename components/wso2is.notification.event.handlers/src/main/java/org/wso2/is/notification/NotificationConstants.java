
/*
 *   Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.is.notification;

/**
 * Constant class used to define notification related constants.
 */
public class NotificationConstants {

    public static final String TOKEN_REVOCATION_EVENT = "token_revocation";
    public static final String TOKEN_REVOCATION_BATCH_EVENT = "token_revocation_batch";
    public static final String NOTIFICATION_ENDPOINT = "notification_endpoint";
    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";
    public static final String HEADER_PROPERTY = "header.";
    public static final String ENVIRONMENT_VARIABLE_STARTING_CHAR = "${";
    public static final String ENVIRONMENT_VARIABLE_ENDING_CHAR = "}";
    public static final String CARBON_CONTEXT = "carbon.context";
    public static final String ADMIN_USER_NAME_SYSTEM_PROPERTY = "admin.username";
    public static final String ADMIN_PASSWORD_SYSTEM_PROPERTY = "admin.password";
    public static final String CARBON_HOME_SYSTEM_PROPERTY = "carbon.home";
    public static final String DOT = ".";

    /**
     * Audit Log Constants
     */
    static class AuditLogConstants {

        static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
        static final String AUDIENCE = "audience";
        static final String CLIENT_ID = "client_id";
        static final String GRANT_TYPE = "grant_type";
        static final String ISSUER = "issuer";
        static final String ISSUED_AT = "iat";
        static final String JWT_ID = "jti";
        static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
        static final String REQUESTED_TOKEN_TYPE = "requested_token_type";
        static final String SUBJECT_TOKEN = "subject_token";
        static final String SUBJECT_TOKEN_TYPE = "subject_token_type";
        static final String TOKEN_EXCHANGE = "Token Exchange";
        static final String TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
        static final String TOKEN_GENERATION = "Token Generation";
        static final String SUBJECT_TOKEN_INFO = "subject_token_info";
        static final String ISSUED_TOKEN_INFO = "issued_token_info";
    }
}
