/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com)
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

package org.wso2.is7.client.model;

import feign.Response;
import feign.Util;
import feign.codec.ErrorDecoder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.is7.client.exceptions.TenantBadRequestException;
import org.wso2.is7.client.exceptions.TenantNotFoundException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Error decoder for tenant management client exceptions
 */
public class TenantManagementErrorDecoder implements ErrorDecoder {

    private static final Log log = LogFactory.getLog(TenantManagementErrorDecoder.class);
    private final ErrorDecoder defaultDecoder = new Default();

    @Override
    public Exception decode(String methodKey, Response response) {

        String errorMessage = getErrorMessage(response);

        // Map HTTP status codes to your custom exceptions.
        switch (response.status()) {
            case 400:
                return new TenantBadRequestException(errorMessage);
            case 404:
                return new TenantNotFoundException(errorMessage);
            default:
                // For all other HTTP error codes, fall back to the default Feign behavior.
                return defaultDecoder.decode(methodKey, response);
        }
    }

    /**
     * Attempts to read the error message from the response body.
     */
    private String getErrorMessage(Response response) {

        try {
            if (response.body() != null) {
                // Read the body and return it as a string.
                // In a real application, you might parse this if it's JSON.
                return Util.toString(response.body().asReader(StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            // Ignore
            log.error("Error occurred when reading response body", e);
        }
        return "Error occurred for request. Status: " + response.status() + ", Reason: " + response.reason();
    }
}

