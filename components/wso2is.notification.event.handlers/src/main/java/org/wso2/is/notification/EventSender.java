
/*
 *   Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
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

import com.google.gson.Gson;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.wso2.is.notification.event.Event;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 *Utility class to push events.
 */
public class EventSender {

    private static final Log log = LogFactory.getLog(EventSender.class);
    private static final EventSender instance = new EventSender();
    private static final ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(200, 500, 100L,
            TimeUnit.SECONDS,
            new LinkedBlockingDeque<Runnable>() {
            });

    private EventSender() {

    }

    public void execute(EventSender.EventRunner eventRunner) {

        threadPoolExecutor.execute(eventRunner);
    }

    public static EventSender getInstance() {

        return instance;
    }

    /**
     * Runnable Thread to send Event
     */
    public static class EventRunner implements Runnable {

        private String notificationEndpoint;
        private Map<String, String> headers;
        private Event event;

        public EventRunner(String notificationEndpoint, Map<String, String> headers, Event event) {

            this.notificationEndpoint = notificationEndpoint;
            this.headers = headers;
            this.event = event;
        }

        @Override
        public void run() {

            try (CloseableHttpClient closeableHttpClient = HttpClientBuilder.create().useSystemProperties().build()) {
                HttpPost httpPost = new HttpPost(notificationEndpoint);
                headers.forEach((key, value) -> {
                    httpPost.addHeader(key, value);
                });
                String content = new Gson().toJson(event);
                StringEntity requestEntity = new StringEntity(content);
                requestEntity.setContentType("application/json");
                httpPost.setEntity(requestEntity);
                try (CloseableHttpResponse execute = closeableHttpClient.execute(httpPost)) {
                }
            } catch (IOException e) {
                log.error("Error while sending Revocation Event to " + notificationEndpoint, e);
            }
        }
    }
}
