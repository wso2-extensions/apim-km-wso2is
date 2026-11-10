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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Keep-alive HTTP stub that accepts one connection and reports whether the client closed it after the response.
 */
public class OneShotHttpServer implements AutoCloseable {

    private final ServerSocket serverSocket;
    private final int status;
    private final long closeWaitMillis;
    private final CountDownLatch done = new CountDownLatch(1);
    private volatile String request;
    private volatile Boolean clientClosed;
    private volatile Throwable failure;

    /**
     * Starts the stub on an ephemeral loopback port.
     *
     * @param status          HTTP status to return
     * @param closeWaitMillis how long to wait for the client to close the connection
     * @throws IOException if the server socket cannot be opened
     */
    public OneShotHttpServer(int status, long closeWaitMillis) throws IOException {

        this.status = status;
        this.closeWaitMillis = closeWaitMillis;
        this.serverSocket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        Thread worker = new Thread(this::serve, "one-shot-http-stub");
        worker.setDaemon(true);
        worker.start();
    }

    /**
     * Returns the notify URL served by this stub.
     *
     * @return endpoint URL
     */
    public String getEndpoint() {

        return "http://127.0.0.1:" + serverSocket.getLocalPort() + "/internal/data/v1/notify";
    }

    /**
     * Waits until the exchange finishes and returns whether the client closed its side of the connection.
     *
     * @param timeoutMillis maximum time to wait
     * @return true if the client sent FIN after the response, false if the connection stayed open
     * @throws Exception if the stub failed or no request arrived in time
     */
    public boolean awaitClientClosed(long timeoutMillis) throws Exception {

        if (!done.await(timeoutMillis, TimeUnit.MILLISECONDS)) {
            throw new IllegalStateException("No notification request received by the stub");
        }
        if (failure != null) {
            throw new IllegalStateException("Stub failed", failure);
        }
        return clientClosed;
    }

    /**
     * Returns the raw request (headers and body) received by the stub.
     *
     * @return raw request text
     */
    public String getRequest() {

        return request;
    }

    private void serve() {

        try (Socket socket = serverSocket.accept()) {
            InputStream in = socket.getInputStream();
            request = readRequest(in);
            OutputStream out = socket.getOutputStream();
            out.write(("HTTP/1.1 " + status + " Stub\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            out.flush();
            socket.setSoTimeout((int) closeWaitMillis);
            try {
                clientClosed = in.read() == -1;
            } catch (SocketTimeoutException e) {
                clientClosed = false;
            }
        } catch (Throwable t) {
            failure = t;
        } finally {
            done.countDown();
        }
    }

    private static String readRequest(InputStream in) throws IOException {

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            buffer.write(b);
            String soFar = new String(buffer.toByteArray(), StandardCharsets.US_ASCII);
            if (soFar.endsWith("\r\n\r\n")) {
                break;
            }
        }
        String head = new String(buffer.toByteArray(), StandardCharsets.US_ASCII);
        int contentLength = 0;
        for (String line : head.split("\r\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
                contentLength = Integer.parseInt(line.substring("content-length:".length()).trim());
            }
        }
        byte[] body = new byte[contentLength];
        int read = 0;
        while (read < contentLength) {
            int n = in.read(body, read, contentLength - read);
            if (n == -1) {
                break;
            }
            read += n;
        }
        return head + new String(body, 0, read, StandardCharsets.UTF_8);
    }

    @Override
    public void close() throws IOException {

        serverSocket.close();
    }
}
