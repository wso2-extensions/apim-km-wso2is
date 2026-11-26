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
import org.junit.Assume;
import org.junit.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;

/**
 * Tests for {@link BasicAuthInterceptorUtil}.
 */
public class BasicAuthInterceptorUtilTest {

    private static final String USERNAME = "user1";
    private static final String LATIN1_PASSWORD = "Test@dmin\u00A32026";
    private static final String NON_LATIN1_PASSWORD = "Test@dmin\u20AC2026";
    private static final String ASCII_PASSWORD = "Test@dmin#2026!$%&'()*+,-./:;<=>?[]^_`{|}~";

    @Test
    public void testResolveCharsetWhenNotConfigured() {

        Assert.assertEquals(StandardCharsets.UTF_8, BasicAuthInterceptorUtil.resolveCharset(null));
        Assert.assertEquals(StandardCharsets.UTF_8, BasicAuthInterceptorUtil.resolveCharset(""));
        Assert.assertEquals(StandardCharsets.UTF_8, BasicAuthInterceptorUtil.resolveCharset("   "));
    }

    @Test
    public void testResolveCharsetWithValidNames() {

        Assert.assertEquals(StandardCharsets.UTF_8, BasicAuthInterceptorUtil.resolveCharset("UTF8"));
        Assert.assertEquals(StandardCharsets.UTF_8, BasicAuthInterceptorUtil.resolveCharset("UTF-8"));
        Assert.assertEquals(StandardCharsets.UTF_8, BasicAuthInterceptorUtil.resolveCharset("utf-8"));
        Assert.assertEquals(StandardCharsets.UTF_8, BasicAuthInterceptorUtil.resolveCharset(" UTF-8 "));
        Assert.assertEquals(StandardCharsets.ISO_8859_1, BasicAuthInterceptorUtil.resolveCharset("ISO-8859-1"));
        Assert.assertEquals(StandardCharsets.ISO_8859_1, BasicAuthInterceptorUtil.resolveCharset("iso-8859-1"));
    }

    @Test
    public void testResolveCharsetWithInvalidNames() {

        Assert.assertEquals(StandardCharsets.UTF_8, BasicAuthInterceptorUtil.resolveCharset("UTF 8"));
        Assert.assertEquals(StandardCharsets.UTF_8, BasicAuthInterceptorUtil.resolveCharset("NOT-A-CHARSET"));
    }

    @Test
    public void testResolveCharsetWithUnsupportedCharsets() {

        // Valid JVM charsets other than UTF-8 and ISO-8859-1 are ignored: they would change or break the encoding.
        Assert.assertEquals(StandardCharsets.UTF_8, BasicAuthInterceptorUtil.resolveCharset("UTF-16"));
        Assert.assertEquals(StandardCharsets.UTF_8, BasicAuthInterceptorUtil.resolveCharset("US-ASCII"));
        Assert.assertEquals(StandardCharsets.UTF_8, BasicAuthInterceptorUtil.resolveCharset("windows-1252"));
    }

    @Test
    public void testPublicFactoryUsesUtf8WhenPropertyNotSet() {

        // The public factory uses the charset from the system property. Without it, UTF-8 is used.
        Assume.assumeTrue(System.getProperty(BasicAuthInterceptorUtil.BASIC_AUTH_CHARSET_PROPERTY) == null);
        Assert.assertArrayEquals((USERNAME + ":" + LATIN1_PASSWORD).getBytes(StandardCharsets.UTF_8),
                decodeCredentials(BasicAuthInterceptorUtil.createBasicAuthInterceptor(USERNAME, LATIN1_PASSWORD)));
        Assert.assertArrayEquals((USERNAME + ":" + NON_LATIN1_PASSWORD).getBytes(StandardCharsets.UTF_8),
                decodeCredentials(BasicAuthInterceptorUtil.createBasicAuthInterceptor(USERNAME,
                        NON_LATIN1_PASSWORD)));
    }

    @Test
    public void testInterceptorWithUtf8Charset() {

        assertCredentialsEncodedWith(LATIN1_PASSWORD, StandardCharsets.UTF_8);
        assertCredentialsEncodedWith(NON_LATIN1_PASSWORD, StandardCharsets.UTF_8);
    }

    @Test
    public void testIso88591KeepsPreviousEncoding() {

        // ISO-8859-1 gives the same header as Feign's 2-argument interceptor, which earlier versions used.
        BasicAuthRequestInterceptor previous = new BasicAuthRequestInterceptor(USERNAME, LATIN1_PASSWORD);
        BasicAuthRequestInterceptor interceptor = BasicAuthInterceptorUtil.createBasicAuthInterceptor(USERNAME,
                LATIN1_PASSWORD, BasicAuthInterceptorUtil.resolveCharset("ISO-8859-1"));

        Assert.assertEquals(getAuthorizationHeader(previous), getAuthorizationHeader(interceptor));
        assertCredentialsEncodedWith(LATIN1_PASSWORD, StandardCharsets.ISO_8859_1);
        // The charset must change the bytes: ISO-8859-1 and UTF-8 differ for a non-ASCII password.
        Assert.assertNotEquals(getAuthorizationHeader(interceptor), getAuthorizationHeader(BasicAuthInterceptorUtil
                .createBasicAuthInterceptor(USERNAME, LATIN1_PASSWORD, StandardCharsets.UTF_8)));
    }

    @Test
    public void testAsciiCredentialsAreSameForAllCharsets() {

        String previousHeader = getAuthorizationHeader(new BasicAuthRequestInterceptor(USERNAME, ASCII_PASSWORD));
        Assert.assertEquals(previousHeader, getAuthorizationHeader(BasicAuthInterceptorUtil
                .createBasicAuthInterceptor(USERNAME, ASCII_PASSWORD, StandardCharsets.UTF_8)));
        Assert.assertEquals(previousHeader, getAuthorizationHeader(BasicAuthInterceptorUtil
                .createBasicAuthInterceptor(USERNAME, ASCII_PASSWORD, StandardCharsets.ISO_8859_1)));
    }

    private static void assertCredentialsEncodedWith(String password, Charset charset) {

        BasicAuthRequestInterceptor interceptor =
                BasicAuthInterceptorUtil.createBasicAuthInterceptor(USERNAME, password, charset);
        Assert.assertArrayEquals((USERNAME + ":" + password).getBytes(charset), decodeCredentials(interceptor));
    }

    private static byte[] decodeCredentials(BasicAuthRequestInterceptor interceptor) {

        String header = getAuthorizationHeader(interceptor);
        Assert.assertTrue(header.startsWith("Basic "));
        return Base64.getDecoder().decode(header.substring("Basic ".length()));
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
