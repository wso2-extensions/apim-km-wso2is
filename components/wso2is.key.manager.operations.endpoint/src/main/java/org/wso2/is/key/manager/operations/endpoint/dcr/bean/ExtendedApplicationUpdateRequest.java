/**
 *
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
}
