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
import org.wso2.carbon.identity.oauth2.validators.scope.ScopeValidator;

import java.util.List;

/**
 * Unit tests for the scope-validator registry added to {@link ServiceReferenceHolder}.
 */
public class ServiceReferenceHolderTest {

    @Before
    public void init() {

        ServiceReferenceHolder.getInstance().getScopeValidators().clear();
    }

    @After
    public void cleanup() {

        ServiceReferenceHolder.getInstance().getScopeValidators().clear();
    }

    @Test
    public void testAddScopeValidator() {

        ScopeValidator validator = Mockito.mock(ScopeValidator.class);
        ServiceReferenceHolder.getInstance().addScopeValidator(validator);

        List<ScopeValidator> validators = ServiceReferenceHolder.getInstance().getScopeValidators();
        Assert.assertEquals("Registry should hold exactly one validator after a single add; got " + validators,
                1, validators.size());
        Assert.assertTrue("Added validator should be present in the registry", validators.contains(validator));
    }

    @Test
    public void testAddMultipleScopeValidators() {

        ScopeValidator validator1 = Mockito.mock(ScopeValidator.class);
        ScopeValidator validator2 = Mockito.mock(ScopeValidator.class);
        ServiceReferenceHolder.getInstance().addScopeValidator(validator1);
        ServiceReferenceHolder.getInstance().addScopeValidator(validator2);

        List<ScopeValidator> validators = ServiceReferenceHolder.getInstance().getScopeValidators();
        Assert.assertEquals("Registry should hold both added validators; got " + validators, 2, validators.size());
        Assert.assertTrue("First added validator should be present", validators.contains(validator1));
        Assert.assertTrue("Second added validator should be present", validators.contains(validator2));
    }

    @Test
    public void testRemoveScopeValidator() {

        ScopeValidator validator1 = Mockito.mock(ScopeValidator.class);
        ScopeValidator validator2 = Mockito.mock(ScopeValidator.class);
        ServiceReferenceHolder.getInstance().addScopeValidator(validator1);
        ServiceReferenceHolder.getInstance().addScopeValidator(validator2);

        ServiceReferenceHolder.getInstance().removeScopeValidator(validator1);

        List<ScopeValidator> validators = ServiceReferenceHolder.getInstance().getScopeValidators();
        Assert.assertEquals("Registry should hold one validator after removing one of two; got " + validators,
                1, validators.size());
        Assert.assertFalse("Removed validator should no longer be present", validators.contains(validator1));
        Assert.assertTrue("Remaining validator should still be present", validators.contains(validator2));
    }

    @Test
    public void testGetScopeValidatorsInitiallyEmpty() {

        Assert.assertTrue("A freshly cleared registry should report empty",
                ServiceReferenceHolder.getInstance().getScopeValidators().isEmpty());
    }

    @Test
    public void testRemoveScopeValidatorNotPresentIsNoOp() {

        ScopeValidator validator = Mockito.mock(ScopeValidator.class);
        ServiceReferenceHolder.getInstance().removeScopeValidator(validator);

        Assert.assertTrue("Removing a validator that was never added should be a no-op and leave the registry empty",
                ServiceReferenceHolder.getInstance().getScopeValidators().isEmpty());
    }
}
