/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationUpdateRequest;

/**
 * This class used to send update request to oauth application
 */
public class ExtendedApplicationUpdateRequest extends ApplicationUpdateRequest {

    private static final long serialVersionUID = -1L;

    private Long applicationAccessTokenLifeTime;
    private Long userAccessTokenLifeTime;
    private Long refreshTokenLifeTime;
    private Long idTokenLifeTime;
    private String applicationDisplayName;
    private Boolean pkceMandatory = false;
    private Boolean pkceSupportPlain = false;
    private Boolean bypassClientCredentials = false;

    public void setApplicationAccessTokenLifeTime(Long applicationAccessTokenLifeTime) {

        this.applicationAccessTokenLifeTime = applicationAccessTokenLifeTime;
    }

    public Long getApplicationAccessTokenLifeTime() {

        return applicationAccessTokenLifeTime;
    }

    public void setUserAccessTokenLifeTime(Long userAccessTokenLifeTime) {

        this.userAccessTokenLifeTime = userAccessTokenLifeTime;
    }

    public Long getUserAccessTokenLifeTime() {

        return userAccessTokenLifeTime;
    }

    public void setRefreshTokenLifeTime(Long refreshTokenLifeTime) {

        this.refreshTokenLifeTime = refreshTokenLifeTime;
    }

    public Long getRefreshTokenLifeTime() {

        return refreshTokenLifeTime;
    }

    public void setIdTokenLifeTime(Long idTokenLifeTime) {

        this.idTokenLifeTime = idTokenLifeTime;
    }

    public Long getIdTokenLifeTime() {

        return idTokenLifeTime;
    }

    public void setApplicationDisplayName(String applicationDisplayName) {

        this.applicationDisplayName = applicationDisplayName;
    }

    public String getApplicationDisplayName() {

        return applicationDisplayName;
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
}
