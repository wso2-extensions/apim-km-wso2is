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
 * SQL Queries related to tokens.
 */
public class SQLQueries {

    public static final String IS_INVALID_TOKEN = "SELECT 1 FROM IDN_OAUTH2_ACCESS_TOKEN WHERE "
            + "(ACCESS_TOKEN_HASH=? OR REFRESH_TOKEN_HASH=?) AND (TOKEN_STATE='INACTIVE' OR TOKEN_STATE='REVOKED' OR "
            + "TOKEN_STATE='EXPIRED'))";

}
