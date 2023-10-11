package org.wso2.is.notification.event;

import org.wso2.is.notification.NotificationConstants;

import java.util.Map;
import java.util.UUID;

/**
 * Internal Token Revocation User Event Model
 */
public class InternalTokenRevocationUserEvent extends Event {
    private static final long serialVersionUID = 1L;

    private long revocationTime;
    private String userUUID;

    public InternalTokenRevocationUserEvent(String userUUID, Map<String, Object> params) {
        this.eventId = UUID.randomUUID().toString();
        this.timeStamp = System.currentTimeMillis();
        this.type = NotificationConstants.INTERNAL_TOKEN_REVOCATION_USER_EVENT;
        this.tenantId = (int) params.get("tenantID");
        this.tenantDomain = params.get("tenantDomain").toString();
        this.userUUID = userUUID;
        this.revocationTime = (long) params.get("revocationTime");
    }
}
