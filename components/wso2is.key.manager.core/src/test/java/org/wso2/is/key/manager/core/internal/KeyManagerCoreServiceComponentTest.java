/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
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
package org.wso2.is.key.manager.core.internal;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.powermock.reflect.Whitebox;
import org.wso2.carbon.identity.oauth2.validators.scope.ScopeValidator;

import java.util.List;

/**
 * Unit tests for the {@code scope.validator.service} bind/unbind methods added to
 * {@link KeyManagerCoreServiceComponent}.
 */
public class KeyManagerCoreServiceComponentTest {

    private KeyManagerCoreServiceComponent component;

    @Before
    public void init() {

        component = new KeyManagerCoreServiceComponent();
        ServiceReferenceHolder.getInstance().getScopeValidators().clear();
    }

    @After
    public void cleanup() {

        ServiceReferenceHolder.getInstance().getScopeValidators().clear();
    }

    @Test
    public void testAddScopeValidatorService() throws Exception {

        ScopeValidator validator = Mockito.mock(ScopeValidator.class);
        Mockito.when(validator.getName()).thenReturn("Test scope validator");

        Whitebox.invokeMethod(component, "addScopeValidatorService", validator);

        List<ScopeValidator> validators = ServiceReferenceHolder.getInstance().getScopeValidators();
        Assert.assertEquals(1, validators.size());
        Assert.assertTrue(validators.contains(validator));
    }

    @Test
    public void testRemoveScopeValidatorService() throws Exception {

        ScopeValidator validator = Mockito.mock(ScopeValidator.class);
        Mockito.when(validator.getName()).thenReturn("Test scope validator");

        Whitebox.invokeMethod(component, "addScopeValidatorService", validator);
        Whitebox.invokeMethod(component, "removeScopeValidatorService", validator);

        Assert.assertTrue(ServiceReferenceHolder.getInstance().getScopeValidators().isEmpty());
    }
}
