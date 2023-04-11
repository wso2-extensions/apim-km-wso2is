/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.is.key.manager.tokenpersistence.model.InvalidTokenPersistenceService;
import org.wso2.is.key.manager.tokenpersistence.utils.DBUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

/**
 * 
 * RDBMS based invalid token persistence implementation
 *
 */
public class DBInvalidTokenPersistence implements InvalidTokenPersistenceService {
    private static final Log log = LogFactory.getLog(DBInvalidTokenPersistence.class);
    private static DBInvalidTokenPersistence instance = null;
    
    public static final String IS_INVALID_TOKEN =
            "SELECT 1 FROM AM_INVALID_TOKENS WHERE SIGNATURE = ? AND TOKEN_TYPE = ? AND CONSUMER_KEY = ? ";
    
    public static final String INSERT_INVALID_TOKEN = 
            "INSERT INTO AM_INVALID_TOKENS (UUID, SIGNATURE, CONSUMER_KEY, TOKEN_TYPE, EXPIRY_TIMESTAMP) "
            + "VALUES (?,?,?,?,?)";
    
    private DBInvalidTokenPersistence() {

    }
    public static synchronized DBInvalidTokenPersistence getInstance() {

        if (instance == null) {
            instance = new DBInvalidTokenPersistence();     
        }
        return instance;
    }
    
    
    @Override
    public boolean isInvalidToken(String token, String type, String consumerKey) throws IdentityOAuth2Exception {
        log.debug("Validate invalid token from the database.");
        try (Connection connection = DBUtil.getConnection()) {
            try (PreparedStatement preparedStatement = connection.prepareStatement(IS_INVALID_TOKEN)) {
                preparedStatement.setString(1, token);
                preparedStatement.setString(2, type);
                preparedStatement.setString(3, consumerKey);
                try (ResultSet resultSet = preparedStatement.executeQuery()) {
                    return resultSet.next();
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while checking existence of token as an invalid token.", e);
        }
    }

    @Override
    public void addInvalidToken(String token, String type, String consumerKey, Long expiryTime)
            throws IdentityOAuth2Exception {
        log.debug("Insert invalid toke to the database");
        try (Connection connection = DBUtil.getConnection()) {
            try (PreparedStatement preparedStatement = connection.prepareStatement(INSERT_INVALID_TOKEN)) {
                connection.setAutoCommit(false);
                preparedStatement.setString(1, UUID.randomUUID().toString());
                preparedStatement.setString(2, token);
                preparedStatement.setString(3, consumerKey);
                preparedStatement.setString(4, type);
                preparedStatement.setLong(5, expiryTime);
                preparedStatement.executeUpdate();
                connection.commit();
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while checking existence of token as an invalid token.", e);
        }
    }

}
