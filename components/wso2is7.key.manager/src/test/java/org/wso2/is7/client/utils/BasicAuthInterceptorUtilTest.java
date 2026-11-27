/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.is7.client.utils;

import feign.RequestTemplate;
import feign.auth.BasicAuthRequestInterceptor;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;

/**
 * Tests for {@link BasicAuthInterceptorUtil}.
 */
public class BasicAuthInterceptorUtilTest {

    private static final String USERNAME = "user1";
    private static final String NON_ASCII_USERNAME = "us\u00E9r1";
    private static final String LATIN1_PASSWORD = "Test@dmin\u00A32026";
    private static final String NON_LATIN1_PASSWORD = "Test@dmin\u20AC2026";
    private static final String ASCII_PASSWORD = "Test@dmin#2026!$%&'()*+,-./:;<=>?[]^_`{|}~";

    @Test
    public void testLatin1CredentialsAreEncodedAsUtf8() {

        assertEncodedAsUtf8(USERNAME, LATIN1_PASSWORD);
        assertEncodedAsUtf8(NON_ASCII_USERNAME, ASCII_PASSWORD);
        // Feign's two-argument constructor encodes as ISO-8859-1, which gives different bytes.
        Assert.assertNotEquals(getAuthorizationHeader(new BasicAuthRequestInterceptor(USERNAME, LATIN1_PASSWORD)),
                getAuthorizationHeader(BasicAuthInterceptorUtil.createBasicAuthInterceptor(USERNAME, LATIN1_PASSWORD)));
    }

    @Test
    public void testNonLatin1CredentialsAreEncodedAsUtf8() {

        // ISO-8859-1 has no euro sign, so Feign's two-argument constructor sends it as '?'.
        assertEncodedAsUtf8(USERNAME, NON_LATIN1_PASSWORD);
    }

    @Test
    public void testAsciiCredentialsAreSameAsBefore() {

        Assert.assertEquals(getAuthorizationHeader(new BasicAuthRequestInterceptor(USERNAME, ASCII_PASSWORD)),
                getAuthorizationHeader(BasicAuthInterceptorUtil.createBasicAuthInterceptor(USERNAME, ASCII_PASSWORD)));
    }

    private static void assertEncodedAsUtf8(String username, String password) {

        String header = getAuthorizationHeader(BasicAuthInterceptorUtil.createBasicAuthInterceptor(username, password));
        Assert.assertTrue(header.startsWith("Basic "));
        byte[] credentials = Base64.getDecoder().decode(header.substring("Basic ".length()));
        Assert.assertArrayEquals((username + ":" + password).getBytes(StandardCharsets.UTF_8), credentials);
        Assert.assertEquals(username + ":" + password, new String(credentials, StandardCharsets.UTF_8));
    }

    private static String getAuthorizationHeader(BasicAuthRequestInterceptor interceptor) {

        RequestTemplate template = new RequestTemplate();
        interceptor.apply(template);
        Collection<String> values = template.headers().get("Authorization");
        Assert.assertNotNull(values);
        Assert.assertEquals(1, values.size());
        return values.iterator().next();
    }
}
