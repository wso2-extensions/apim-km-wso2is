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
 * Represents the tenant creation request payload for WSO2 Identity Server 7.
 * From Here : https://github.com/wso2/identity-api-server/blob/master/
 * components/org.wso2.carbon.identity.api.server.tenant.management/
 * org.wso2.carbon.identity.api.server.tenant.management.v1/src/gen/java/org/wso2/carbon/identity/api/server/tenant/
 * management/v1/model/TenantModel.java
 */
public class TenantModel {

    public TenantModel() {}

    @SerializedName("domain")
    private String domain;

    @SerializedName("name")
    private String name;

    @SerializedName("owners")
    private List<Owner> owners;


    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }

    public List<Owner> getOwners() {
        return owners;
    }

    public void setOwners(List<Owner> owners) {
        this.owners = owners;
    }

    /**
     * Represents the owner of the tenant.
     **/
    public static class Owner {
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
        private List<AdditionalClaims> additionalClaims = null;

        public Owner(String username, String password, String email, String firstname, String lastname,
                     String provisioningMethod, List<AdditionalClaims> additionalClaims) {
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

        public List<AdditionalClaims> getAdditionalClaims() {
            return additionalClaims;
        }

        public void setAdditionalClaims(List<AdditionalClaims> additionalClaims) {
            this.additionalClaims = additionalClaims;
        }
    }

    /**
     * Represents additional claims for the tenant owner.
     */
    public static class AdditionalClaims {
        @SerializedName("claim")
        private String claim;

        @SerializedName("value")
        private String value;

        public String getClaim() {
            return claim;
        }

        public void setClaim(String claim) {
            this.claim = claim;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }

    /**
     * Represents the request payload to update an owner of a tenant.
     */
    public static class OwnerPutModel {
        @SerializedName("email")
        private String email;

        @SerializedName("password")
        private String password;

        @SerializedName("firstname")
        private String firstname;

        @SerializedName("lastname")
        private String lastname;

        @SerializedName("additionalClaims")
        private List<AdditionalClaims> additionalClaims = null;

        public String getEmail() {
            return email;
        }
        public void setEmail(String email) {
            this.email = email;
        }
        public String getPassword() {
            return password;
        }
        public void setPassword(String password) {
            this.password = password;
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
        public List<AdditionalClaims> getAdditionalClaims() {
            return additionalClaims;
        }
        public void setAdditionalClaims(List<AdditionalClaims> additionalClaims) {
            this.additionalClaims = additionalClaims;
        }

        public OwnerPutModel(String email, String password, String firstname, String lastname,
                             List<AdditionalClaims> additionalClaims) {
            this.email = email;
            this.password = password;
            this.firstname = firstname;
            this.lastname = lastname;
            this.additionalClaims = additionalClaims;
        }
    }

    /**
     * Represents the request payload to update the lifecycle status of a tenant.
     */
    public static class TenantPutModel {
        public TenantPutModel(boolean activated) {
            this.activated = activated;
        }
        private Boolean activated;

        public Boolean getActivated() {
            return activated;
        }
        public void setActivated(Boolean activated) {
            this.activated = activated;
        }
    }
}
