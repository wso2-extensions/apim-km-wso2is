/*
 * Copyright (c) 2026, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.is7.client;

import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

public class WSO2IS7KeyManagerTest {

    private WSO2IS7KeyManager keyManager;

    @Before
    public void setUp() {
        keyManager = mock(WSO2IS7KeyManager.class);
    }

    private String[] invokeExtractCallbackURLs(String callBackURL) throws Exception {
        Method method = WSO2IS7KeyManager.class.getDeclaredMethod("extractCallbackURLs", String.class);
        method.setAccessible(true);
        return (String[]) method.invoke(keyManager, callBackURL);
    }

    private String invokeBuildCallBackURL(List<String> redirectUris) throws Exception {
        Method method = WSO2IS7KeyManager.class.getDeclaredMethod("buildCallbackURL", List.class);
        method.setAccessible(true);
        return (String) method.invoke(keyManager, redirectUris);
    }

    @Test
    public void testExtractCallbackURLsSingleURL() throws Exception {
        String[] result = invokeExtractCallbackURLs("http://hello:9443");
        assertArrayEquals(new String[]{"http://hello:9443"}, result);
    }

    @Test
    public void testExtractCallbackURLsCommaSeparated() throws Exception {
        String[] result = invokeExtractCallbackURLs("http://hello:9443,https://heloo123");
        assertArrayEquals(new String[]{"http://hello:9443", "https://heloo123"}, result);
    }

    @Test
    public void testExtractCallbackURLsCommaSeparatedWithSpaces() throws Exception {
        String[] result = invokeExtractCallbackURLs("http://hello:9443 , https://heloo123 , https://third");
        assertArrayEquals(new String[]{"http://hello:9443", "https://heloo123", "https://third"}, result);
    }

    @Test
    public void testExtractCallbackURLsRegexpFormatTwoURLs() throws Exception {
        String[] result = invokeExtractCallbackURLs("regexp=(http://hello:9443|https://heloo123)");
        assertArrayEquals(new String[]{"http://hello:9443", "https://heloo123"}, result);
    }

    @Test
    public void testExtractCallbackURLsRegexpFormatThreeURLs() throws Exception {
        String[] result = invokeExtractCallbackURLs("regexp=(http://a|http://b|http://c)");
        assertArrayEquals(new String[]{"http://a", "http://b", "http://c"}, result);
    }

    @Test
    public void testBuildCallBackURLSingleURL() throws Exception {
        String result = invokeBuildCallBackURL(Collections.singletonList("http://hello:9443"));
        assertEquals("http://hello:9443", result);
    }

    @Test
    public void testBuildCallBackURLRegexpFormatTwoURLs() throws Exception {
        String result = invokeBuildCallBackURL(
                Collections.singletonList("regexp=(http://hello:9443|https://heloo123)"));
        assertEquals("http://hello:9443,https://heloo123", result);
    }

    @Test
    public void testBuildCallBackURLRegexpFormatThreeURLs() throws Exception {
        String result = invokeBuildCallBackURL(Collections.singletonList("regexp=(http://a|http://b|http://c)"));
        assertEquals("http://a,http://b,http://c", result);
    }

    @Test
    public void testBuildCallBackURLMultipleEntries() throws Exception {
        String result = invokeBuildCallBackURL(Arrays.asList("http://hello:9443", "https://heloo123"));
        assertEquals("http://hello:9443,https://heloo123", result);
    }

    @Test
    public void testBuildCallBackURLEmptyList() throws Exception {
        String result = invokeBuildCallBackURL(Collections.emptyList());
        assertEquals("", result);
    }

    @Test
    public void testRoundTripPreservesOriginalCallbackURLs() throws Exception {
        // Multiple URLs sent to IS get stored/returned encoded as regexp=(url1|url2);
        // a subsequent save must decode that back to the original comma-separated list
        String original = "http://hello:9443,https://heloo123";
        String[] sentToIS = invokeExtractCallbackURLs(original);

        String storedByIS = "regexp=(" + String.join("|", sentToIS) + ")";

        String decodedBack = invokeBuildCallBackURL(Collections.singletonList(storedByIS));
        assertEquals(original, decodedBack);
        assertArrayEquals(sentToIS, invokeExtractCallbackURLs(decodedBack));
    }
}
