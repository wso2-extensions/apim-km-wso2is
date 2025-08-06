/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.is.key.manager.operations.endpoint.dcr.bean;

import org.wso2.carbon.identity.oauth.dcr.bean.Application;

import java.io.Serializable;
import java.util.List;

/**
 * This object contains the context related to OAuth application.
 */
public class ExtendedApplication extends Application implements Serializable {

    private static final long serialVersionUID = -4515815791420125411L;

    private String applicationOwner = null;
    private List<String> grantTypes = null;

    private long applicationAccessTokenLifeTime;
    private long userAccessTokenLifeTime;
    private long refreshTokenLifeTime;
    private long idTokenLifeTime;
    private Boolean pkceMandatory = false;
    private Boolean pkceSupportPlain = false;
    private Boolean bypassClientCredentials = false;
    private String tokenType;
    private List<String> applicationScopes = null;

    public long getApplicationAccessTokenLifeTime() {

        return applicationAccessTokenLifeTime;
    }

    public void setApplicationAccessTokenLifeTime(long applicationAccessTokenLifeTime) {

        this.applicationAccessTokenLifeTime = applicationAccessTokenLifeTime;
    }

    public long getUserAccessTokenLifeTime() {

        return userAccessTokenLifeTime;
    }

    public void setUserAccessTokenLifeTime(long userAccessTokenLifeTime) {

        this.userAccessTokenLifeTime = userAccessTokenLifeTime;
    }

    public long getRefreshTokenLifeTime() {

        return refreshTokenLifeTime;
    }

    public void setRefreshTokenLifeTime(long refreshTokenLifeTime) {

        this.refreshTokenLifeTime = refreshTokenLifeTime;
    }

    public long getIdTokenLifeTime() {

        return idTokenLifeTime;
    }

    public void setIdTokenLifeTime(long idTokenLifeTime) {

        this.idTokenLifeTime = idTokenLifeTime;
    }

    public String getApplicationOwner() {

        return applicationOwner;
    }

    public void setApplicationOwner(String applicationOwner) {

        this.applicationOwner = applicationOwner;
    }

    public List<String> getGrantTypes() {
        return this.grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {
        this.grantTypes = grantTypes;
    }

    public Boolean getPkceMandatory() {
        return pkceMandatory;
    }

    public void setPkceMandatory(Boolean pkceMandatory) {
        this.pkceMandatory = pkceMandatory;
    }

    public Boolean getPkceSupportPlain() {
        return pkceSupportPlain;
    }

    public void setPkceSupportPlain(Boolean pkceSupportPlain) {
        this.pkceSupportPlain = pkceSupportPlain;
    }

    public Boolean getBypassClientCredentials() {
        return bypassClientCredentials;
    }

    public void setBypassClientCredentials(Boolean bypassClientCredentials) {
        this.bypassClientCredentials = bypassClientCredentials;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public List<String> getApplicationScopes() {
        return this.applicationScopes;
    }

    public void setApplicationScopes(List<String> applicationScopes) {
        this.applicationScopes = applicationScopes;
    }

}
