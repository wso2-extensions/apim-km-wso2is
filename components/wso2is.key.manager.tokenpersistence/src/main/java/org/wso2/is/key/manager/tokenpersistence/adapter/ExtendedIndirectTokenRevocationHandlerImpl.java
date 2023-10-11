package org.wso2.is.key.manager.tokenpersistence.adapter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.handler.IndirectTokenRevocationHandler;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.is.key.manager.tokenpersistence.internal.ServiceReferenceHolder;
import org.wso2.is.key.manager.tokenpersistence.listner.APIMOAuthApplicationMgtListener;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Extended implementation of {@link IndirectTokenRevocationHandler}
 * This is used to extend the behaviour of token revocation
 * due to internal user events when using token persistence removal feature
 */
public class ExtendedIndirectTokenRevocationHandlerImpl implements IndirectTokenRevocationHandler {

    private static final Log log = LogFactory.getLog(ExtendedIndirectTokenRevocationHandlerImpl.class);

    @Override
    public boolean revokeTokens(String username, UserStoreManager userStoreManager) throws UserStoreException {
        String userUUID = ((AbstractUserStoreManager) userStoreManager).getUserIDFromUserName(username);
        int tenantID = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantID);

        long revocationTime = Calendar.getInstance().getTimeInMillis();

        Map<String, Object> params = new HashMap<>();
        params.put("userUUID", userUUID);
        params.put("username", username);
        params.put("revocationTime", revocationTime);
        params.put("tenantID", tenantID);
        params.put("tenantDomain", tenantDomain);

        OAuthUtil.invokePreRevocationBySystemListeners(userUUID, params);
        try {
            ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService()
                    .revokeAccessTokensByUserEvent(userUUID, revocationTime);
            revokeAppTokensOfUser(params);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while persisting revoking access tokens by user event.", e);
            return false;
        }
        OAuthUtil.invokePostRevocationBySystemListeners(userUUID, params);

        return true;
    }

    /**
     * Revokes the app tokens of the user.
     *
     * @param params parameters required to revoke the app tokens.
     */
    private void revokeAppTokensOfUser(Map<String, Object> params) {
        // get client ids for the apps owned by user since the 'sub' claim for these are the consumer key.
        // The app tokens for those consumer keys should also be revoked
        Properties properties = new Properties();
        properties.put("revocationTime", params.get("revocationTime"));
        properties.put("tenantID", params.get("tenantID"));
        properties.put("isRevokeAppOnly", true);

        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        try {
            OAuthAppDO[] oAuthAppDOs = oAuthAppDAO
                    .getOAuthConsumerAppsOfUser((String) params.get("username"), (int) params.get("tenantID"));
            APIMOAuthApplicationMgtListener apimoAuthApplicationMgtListener = new APIMOAuthApplicationMgtListener();
            for (OAuthAppDO oAuthAppDO : oAuthAppDOs) {
                apimoAuthApplicationMgtListener
                        .doPostRegenerateClientSecret(oAuthAppDO.getOauthConsumerKey(), properties);
            }
        } catch (IdentityOAuthAdminException e) {
            log.error("Error while revoking app tokens of user by user event", e);
        }
    }
}
