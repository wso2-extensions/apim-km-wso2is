/*
 *   Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
 *
 *   WSO2 LLC. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.is.notification;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.wso2.is.notification.event.TokenRevocationEvent;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Tests that EventSender releases its per-event HTTP connection (issue #20772, CLOSE_WAIT leak on 9443).
 */
public class EventSenderTest {

    private static final long CLOSE_WAIT_MILLIS = 5000L;
    private static final long AWAIT_MILLIS = 15000L;
    private static final String HOSTNAME_VERIFIER = "httpclient.hostnameVerifier";
    private static final String DISABLE_HOSTNAME_VERIFICATION =
            "org.opensaml.httpclient.https.disableHostnameVerification";

    @After
    public void clearSystemProperties() {

        System.clearProperty(HOSTNAME_VERIFIER);
        System.clearProperty(DISABLE_HOSTNAME_VERIFICATION);
    }

    private static TokenRevocationEvent newEvent() {

        return new TokenRevocationEvent("dummy-token", 3600L, "user1", "dummy-client", "Default");
    }

    private static boolean runAndCheckClosed(int status) throws Exception {

        try (OneShotHttpServer server = new OneShotHttpServer(status, CLOSE_WAIT_MILLIS)) {
            new EventSender.EventRunner(server.getEndpoint(), "admin", "admin",
                    Collections.<String, String>emptyMap(), newEvent()).run();
            return server.awaitClientClosed(AWAIT_MILLIS);
        }
    }

    @Test
    public void testConnectionClosedAfterSuccessfulNotification() throws Exception {

        Assert.assertTrue("Notify connection was left open after a 200 response; it would end up in CLOSE_WAIT",
                runAndCheckClosed(200));
    }

    @Test
    public void testConnectionClosedAfterErrorResponse() throws Exception {

        Assert.assertTrue("Notify connection was left open after a 500 response; it would end up in CLOSE_WAIT",
                runAndCheckClosed(500));
    }

    @Test
    public void testConnectionClosedWithAllowAllHostnameVerifier() throws Exception {

        System.setProperty(HOSTNAME_VERIFIER, "AllowAll");
        Assert.assertTrue("Notify connection was left open in the AllowAll branch", runAndCheckClosed(200));
    }

    @Test
    public void testConnectionClosedWithHostnameVerificationDisabled() throws Exception {

        System.setProperty(DISABLE_HOSTNAME_VERIFICATION, "true");
        Assert.assertTrue("Notify connection was left open when hostname verification is disabled",
                runAndCheckClosed(200));
    }

    @Test
    public void testRequestContentUnchanged() throws Exception {

        Map<String, String> headers = new HashMap<>();
        headers.put("X-Test-Header", "test-value");
        try (OneShotHttpServer server = new OneShotHttpServer(200, CLOSE_WAIT_MILLIS)) {
            new EventSender.EventRunner(server.getEndpoint(), "admin", "admin", headers, newEvent()).run();
            Assert.assertTrue(server.awaitClientClosed(AWAIT_MILLIS));
            String request = server.getRequest();
            String expectedAuth = "Basic " + Base64.getEncoder()
                    .encodeToString("admin:admin".getBytes(StandardCharsets.UTF_8));
            Assert.assertTrue(request, request.startsWith("POST /internal/data/v1/notify "));
            Assert.assertTrue(request, request.contains("Authorization: " + expectedAuth));
            Assert.assertTrue(request, request.contains("X-Test-Header: test-value"));
            Assert.assertTrue(request, request.contains("Content-Type: application/json"));
            Assert.assertTrue(request, request.contains("\"accessToken\":\"dummy-token\""));
        }
    }

    @Test
    public void testNoAuthorizationHeaderWithoutCredentials() throws Exception {

        try (OneShotHttpServer server = new OneShotHttpServer(200, CLOSE_WAIT_MILLIS)) {
            new EventSender.EventRunner(server.getEndpoint(), null, null,
                    Collections.<String, String>emptyMap(), newEvent()).run();
            Assert.assertTrue(server.awaitClientClosed(AWAIT_MILLIS));
            Assert.assertFalse(server.getRequest(), server.getRequest().contains("Authorization:"));
        }
    }

    @Test
    public void testUnreachableEndpointDoesNotThrow() throws Exception {

        int port;
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = probe.getLocalPort();
        }
        new EventSender.EventRunner("http://127.0.0.1:" + port + "/internal/data/v1/notify", "admin", "admin",
                Collections.<String, String>emptyMap(), newEvent()).run();
    }

    @Test
    public void testPublishEventClosesConnection() throws Exception {

        try (OneShotHttpServer server = new OneShotHttpServer(200, CLOSE_WAIT_MILLIS)) {
            EventSender sender = new EventSender(server.getEndpoint(), "admin", "admin",
                    Collections.<String, String>emptyMap());
            sender.publishEvent(newEvent());
            Assert.assertTrue("Connection opened by publishEvent was left open; it would end up in CLOSE_WAIT",
                    server.awaitClientClosed(AWAIT_MILLIS));
        }
    }
}
