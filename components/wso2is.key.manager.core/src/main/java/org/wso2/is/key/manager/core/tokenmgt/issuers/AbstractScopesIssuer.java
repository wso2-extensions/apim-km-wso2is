/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.is.key.manager.core.tokenmgt.issuers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.callback.OAuthCallback;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.bean.ScopeBinding;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.is.key.manager.core.internal.ServiceReferenceHolder;
import org.wso2.is.key.manager.core.tokenmgt.handlers.ResourceConstants;
import org.wso2.is.key.manager.core.tokenmgt.util.TokenMgtUtil;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.cache.CacheManager;
import javax.cache.Caching;

import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getAppInformationByClientId;

/**
 * This abstract class represents the basic requirements of a scope issuer.
 */
public abstract class AbstractScopesIssuer {

    private static final String DEFAULT_SCOPE_NAME = "default";
    private static Log log = LogFactory.getLog(AbstractScopesIssuer.class);

    /**
     * This method is used to retrieve the authorized scopes with respect to a token.
     *
     * @param tokReqMsgCtx      token message context
     * @return authorized scopes list
     */
    public abstract List<String> getScopes(OAuthTokenReqMessageContext tokReqMsgCtx);

    /**
     * This method is used to retrieve authorized scopes with respect to an authorization callback.
     *
     * @param scopeValidationCallback Authorization callback to validate scopes
     * @return authorized scopes list
     */
    public abstract List<String> getScopes(OAuthCallback scopeValidationCallback);

    /**
     * This method is used to get the prefix of the scope issuer.
     *
     * @return returns the prefix with respect to an issuer.
     */
    public abstract String getPrefix();

    /**
     * Get the set of default scopes. If a requested scope is matches with the patterns specified in the whitelist,
     * then such scopes will be issued without further validation. If the scope list is empty,
     * token will be issued for default scop1e.
     *
     * @param requestedScopes - The set of requested scopes
     * @return - The subset of scopes that are allowed
     */
    public List<String> getAllowedScopes(List<String> requestedScopes) {

        if (requestedScopes.isEmpty()) {
            requestedScopes.add(DEFAULT_SCOPE_NAME);
        }
        return requestedScopes;
    }

    /**
     * Determines if the scope is specified in the whitelist.
     *
     * @param scope - The scope key to check
     * @return - 'true' if the scope is white listed. 'false' if not.
     */
    public boolean isWhiteListedScope(List<String> scopeSkipList, String scope) {
        for (String scopeTobeSkipped : scopeSkipList) {
            if (scope.matches(scopeTobeSkipped)) {
                return true;
            }
        }
        return false;
    }

    /**
     * This method is used to get the application scopes including the scopes defined for the APIs subscribed to the
     * application and the API-M REST API scopes set of the current tenant.
     *
     * @param consumerKey       Consumer Key of the application
     * @param authenticatedUser Authenticated User
     * @return Application Scope List
     */
    public Map<String, String> getAppScopes(String consumerKey, AuthenticatedUser authenticatedUser,
            List<String> requestedScopes) {

        //Get all the scopes and roles against the scopes defined for the APIs subscribed to the application.
        boolean isTenantFlowStarted = false;
        Map<String, String> appScopes = null;
        Set<Scope> scopes = null;
        String requestedScopesString = String.join(" ", requestedScopes);
        String tenantDomain = null;
        try {
            tenantDomain = getAppInformationByClientId(consumerKey).getAppOwner().getTenantDomain();
            if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                isTenantFlowStarted = true;
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
                TokenMgtUtil.loadTenantConfigBlockingMode(tenantDomain);
            }
            scopes = TokenMgtUtil.getOAuth2ScopeService().getScopes(null, null, true, requestedScopesString);
        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            log.error("Error when retrieving the tenant domain " + e.getMessage(), e);
        } catch (IdentityOAuth2ScopeServerException e) {
            log.error("Error while getting scopes " + e.getMessage(), e);
        } finally {
            if (isTenantFlowStarted) {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }

        //Need to get app scopes via IS tables or service
        if (scopes != null) {
            appScopes = getAppScopes(scopes);
        }
        return appScopes;
    }

    private Map<String, String> getAppScopes(Set<Scope> scopes) {
        Map<String, String> appScopes = new HashMap<>();
        for (Scope scope: scopes) {
            ScopeBinding scopeBinding = getScopeBinding(scope.getScopeBindings());
            String bindings = "";
            if (scopeBinding != null) {
                bindings = String.join(",", scopeBinding.getBindings());
            }

            appScopes.put(scope.getName(), bindings);
        }

        return appScopes;
    }

    private ScopeBinding getScopeBinding(List<ScopeBinding> scopeBindings) {
        for (ScopeBinding scopeBinding: scopeBindings) {
            if (ResourceConstants.OAUTH2_DEFAULT_SCOPE.equalsIgnoreCase(scopeBinding.getBindingType())) {
                return scopeBinding;
            }
        }
        return  null;
    }

    /**
     * This method is used to check if the application scope list empty.
     *
     * @param appScopes Application scopes list
     * @param clientId  Client ID of the application
     * @return if the scopes list is empty
     */
    public Boolean isAppScopesEmpty(Map<String, String> appScopes, String clientId) {

        if (appScopes.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("No scopes defined for the Application " + clientId);
            }
            return true;
        }
        return false;
    }

    /**
     * Get CacheManager instance
     *
     * @param name The name of the Cache
     * @return CacheManager
     */
    protected CacheManager getCacheManager(String name) {
        return Caching.getCacheManager(name);
    }

    /**
     * Get RealmService
     *
     * @return RealmService
     */
    protected RealmService getRealmService() {
        return ServiceReferenceHolder.getInstance().getRealmService();
    }

    /**
     * Get tenant Id of the user
     *
     * @param username Username
     * @return int
     */
    protected int getTenantIdOfUser(String username) {
        return IdentityTenantUtil.getTenantIdOfUser(username);
    }

}
