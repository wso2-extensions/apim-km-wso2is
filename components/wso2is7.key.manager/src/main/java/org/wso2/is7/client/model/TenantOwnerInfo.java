/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com)
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

package org.wso2.is7.client.model;

import com.google.gson.annotations.SerializedName;

import java.util.List;

/**
 * Represents the owner of the tenant.
 **/
public class TenantOwnerInfo {
    @SerializedName("username")
    private String username;

    @SerializedName("password")
    private String password;

    @SerializedName("email")
    private String email;

    @SerializedName("firstname")
    private String firstname;

    @SerializedName("lastname")
    private String lastname;

    @SerializedName("provisioningMethod")
    private String provisioningMethod = "inline-password";

    @SerializedName("additionalClaims")
    private List<TenantAdditionalClaims> additionalClaims = null;

    public TenantOwnerInfo(String username, String password, String email, String firstname, String lastname,
                           String provisioningMethod, List<TenantAdditionalClaims> additionalClaims) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.firstname = firstname;
        this.lastname = lastname;
        this.provisioningMethod = provisioningMethod != null ? provisioningMethod : "inline-password";
        this.additionalClaims = additionalClaims;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getProvisioningMethod() {
        return provisioningMethod;
    }

    public void setProvisioningMethod(String provisioningMethod) {
        this.provisioningMethod = provisioningMethod;
    }

    public List<TenantAdditionalClaims> getAdditionalClaims() {
        return additionalClaims;
    }

    public void setAdditionalClaims(List<TenantAdditionalClaims> additionalClaims) {
        this.additionalClaims = additionalClaims;
    }
}
