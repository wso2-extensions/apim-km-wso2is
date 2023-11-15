/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.is.key.manager.tokenpersistence.dao;

/**
 * SQL Queries related to invalid tokens and internal token revoke events.
 */
public class SQLQueries {

    public static final String IS_INVALID_TOKEN = "SELECT 1 FROM IDN_INVALID_TOKENS WHERE TOKEN_IDENTIFIER = ? AND "
            + "CONSUMER_KEY = ? ";
    public static final String INSERT_INVALID_TOKEN = "INSERT INTO IDN_INVALID_TOKENS (UUID, TOKEN_IDENTIFIER, "
            + "CONSUMER_KEY, EXPIRY_TIMESTAMP) VALUES (?,?,?,?)";
    public static final String DELETE_INVALID_TOKEN = "DELETE FROM IDN_INVALID_TOKENS WHERE EXPIRY_TIMESTAMP < ?";
    public static final String IS_APP_REVOKED_EVENT = "SELECT 1 "
            + "FROM IDN_APP_REVOKED_EVENT WHERE CONSUMER_KEY = ? AND TIME_REVOKED >= ?";
    public static final String INSERT_APP_REVOKED_EVENT = "INSERT INTO IDN_APP_REVOKED_EVENT "
            + "(EVENT_ID, CONSUMER_KEY, TIME_REVOKED, ORGANIZATION) VALUES (?, ?, ?, ?)";
    public static final String UPDATE_APP_REVOKED_EVENT = "UPDATE IDN_APP_REVOKED_EVENT "
            + "SET TIME_REVOKED = ? WHERE CONSUMER_KEY = ? AND ORGANIZATION = ?";
    public static final String IS_SUBJECT_ENTITY_REVOKED_EVENT = "SELECT 1 "
            + "FROM IDN_SUBJECT_ENTITY_REVOKED_EVENT WHERE ENTITY_ID = ? AND TIME_REVOKED >= ?";
    public static final String INSERT_SUBJECT_ENTITY_REVOKED_EVENT = "INSERT INTO IDN_SUBJECT_ENTITY_REVOKED_EVENT "
            + "(EVENT_ID, ENTITY_ID, ENTITY_TYPE, TIME_REVOKED, ORGANIZATION) VALUES (?, ?, ?, ?, ?)";
    public static final String UPDATE_SUBJECT_ENTITY_REVOKED_EVENT = "UPDATE IDN_SUBJECT_ENTITY_REVOKED_EVENT "
            + "SET TIME_REVOKED = ? WHERE ENTITY_ID = ? AND ENTITY_TYPE = ? AND ORGANIZATION = ?";
}
