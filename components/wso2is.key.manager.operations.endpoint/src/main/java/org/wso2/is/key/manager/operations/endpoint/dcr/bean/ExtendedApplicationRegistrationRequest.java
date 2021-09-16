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

import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationRegistrationRequest;

import java.io.Serializable;

/**
 * This object contains the context related to OAuth application registration request.
 */
public class ExtendedApplicationRegistrationRequest extends ApplicationRegistrationRequest implements Serializable {

    private static final long serialVersionUID = -4515815791420125411L;

    private String applicationOwner = null;
    private Long applicationAccessTokenLifeTime;
    private Long userAccessTokenLifeTime;
    private Long refreshTokenLifeTime;
    private Long idTokenLifeTime;
    private String applicationDisplayName;
    private Boolean pkceMandatory = false;
    private Boolean pkceSupportPlain = false;

    public Long getApplicationAccessTokenLifeTime() {

        return applicationAccessTokenLifeTime;
    }

    public void setApplicationAccessTokenLifeTime(Long applicationAccessTokenLifeTime) {

        this.applicationAccessTokenLifeTime = applicationAccessTokenLifeTime;
    }

    public Long getUserAccessTokenLifeTime() {

        return userAccessTokenLifeTime;
    }

    public void setUserAccessTokenLifeTime(Long userAccessTokenLifeTime) {

        this.userAccessTokenLifeTime = userAccessTokenLifeTime;
    }

    public Long getRefreshTokenLifeTime() {

        return refreshTokenLifeTime;
    }

    public void setRefreshTokenLifeTime(Long refreshTokenLifeTime) {

        this.refreshTokenLifeTime = refreshTokenLifeTime;
    }

    public Long getIdTokenLifeTime() {

        return idTokenLifeTime;
    }

    public void setIdTokenLifeTime(Long idTokenLifeTime) {

        this.idTokenLifeTime = idTokenLifeTime;
    }

    /**
     *
     * @return applicationOwner
     */
    public String getApplicationOwner() {

        return applicationOwner;
    }

    public void setApplicationOwner(String applicationOwner) {

        this.applicationOwner = applicationOwner;
    }

    /**
     *
     * @return applicationDisplayName
     */
    public String getApplicationDisplayName() {

        return applicationDisplayName;
    }

    public void setApplicationDisplayName(String applicationDisplayName) {

        this.applicationDisplayName = applicationDisplayName;
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

}
