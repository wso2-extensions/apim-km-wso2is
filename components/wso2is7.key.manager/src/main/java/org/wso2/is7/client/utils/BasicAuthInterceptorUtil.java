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

import feign.auth.BasicAuthRequestInterceptor;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;

/**
 * Creates the Basic authentication request interceptors used by the WSO2 IS7 connector's Feign clients.
 * <p>
 * The credentials are encoded using UTF-8 by default. To use ISO-8859-1, the encoding used by earlier versions,
 * set the {@value #BASIC_AUTH_CHARSET_PROPERTY} system property to ISO-8859-1 (for example
 * {@code -Dwso2is7.km.basic.auth.charset=ISO-8859-1}). Any other value is ignored, with an error log.
 */
public final class BasicAuthInterceptorUtil {

    private static final Log log = LogFactory.getLog(BasicAuthInterceptorUtil.class);

    /**
     * System property used to configure the charset for encoding Basic authentication credentials.
     */
    public static final String BASIC_AUTH_CHARSET_PROPERTY = "wso2is7.km.basic.auth.charset";

    /**
     * Charset used when the system property is not set, or is set to a value that is not supported.
     */
    static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    private static final String FALLBACK_MESSAGE = "Falling back to the default, UTF-8, to encode "
            + "Basic authentication credentials of the WSO2 IS7 Key Manager connector.";

    private static final Charset CONFIGURED_CHARSET = resolveCharset(System.getProperty(BASIC_AUTH_CHARSET_PROPERTY));

    private BasicAuthInterceptorUtil() {

    }

    /**
     * Creates a Basic authentication request interceptor for the given credentials.
     *
     * @param username username
     * @param password password
     * @return Basic authentication request interceptor which encodes the credentials using the configured charset,
     * or UTF-8 if a charset is not configured
     */
    public static BasicAuthRequestInterceptor createBasicAuthInterceptor(String username, String password) {

        return createBasicAuthInterceptor(username, password, CONFIGURED_CHARSET);
    }

    /**
     * Creates a Basic authentication request interceptor for the given credentials and charset.
     *
     * @param username username
     * @param password password
     * @param charset  charset to encode the credentials with
     * @return Basic authentication request interceptor
     */
    static BasicAuthRequestInterceptor createBasicAuthInterceptor(String username, String password,
                                                                  Charset charset) {

        return new BasicAuthRequestInterceptor(username, password, charset);
    }

    /**
     * Resolves the charset from the given charset name. Only UTF-8 and ISO-8859-1 are supported.
     *
     * @param charsetName charset name (for example UTF-8 or ISO-8859-1)
     * @return resolved charset, or UTF-8 if the charset name is empty, invalid or not supported
     */
    static Charset resolveCharset(String charsetName) {

        if (StringUtils.isBlank(charsetName)) {
            return DEFAULT_CHARSET;
        }
        Charset charset;
        try {
            charset = Charset.forName(charsetName.trim());
        } catch (IllegalCharsetNameException | UnsupportedCharsetException e) {
            log.error("Invalid charset: " + charsetName + " configured by the system property: "
                    + BASIC_AUTH_CHARSET_PROPERTY + ". " + FALLBACK_MESSAGE);
            return DEFAULT_CHARSET;
        }
        if (!StandardCharsets.UTF_8.equals(charset) && !StandardCharsets.ISO_8859_1.equals(charset)) {
            log.error("Unsupported charset: " + charset.name() + " configured by the system property: "
                    + BASIC_AUTH_CHARSET_PROPERTY + ". Only UTF-8 and ISO-8859-1 are supported. " + FALLBACK_MESSAGE);
            return DEFAULT_CHARSET;
        }
        log.info("Using charset: " + charset.name() + " to encode Basic authentication credentials of the "
                + "WSO2 IS7 Key Manager connector, as configured by the system property: "
                + BASIC_AUTH_CHARSET_PROPERTY);
        return charset;
    }
}
