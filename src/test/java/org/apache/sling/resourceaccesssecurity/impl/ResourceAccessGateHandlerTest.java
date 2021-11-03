/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.resourceaccesssecurity.impl;

import org.apache.sling.resourceaccesssecurity.ResourceAccessGate;
import org.apache.sling.resourceaccesssecurity.ResourceAccessGate.Operation;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.osgi.framework.ServiceReference;

@RunWith(MockitoJUnitRunner.class)
public class ResourceAccessGateHandlerTest {
    @Mock
    ResourceAccessGate gate;

    @Mock
    ServiceReference<ResourceAccessGate> gateRef;

    @Test
    public void testSingleValueProperties() {
        Mockito.when(gateRef.getProperty(ResourceAccessGate.PATH)).thenReturn("/content");
        Mockito.when(gateRef.getProperty(ResourceAccessGate.OPERATIONS)).thenReturn("read");
        Mockito.when(gateRef.getProperty(ResourceAccessGate.FINALOPERATIONS)).thenReturn("read");
        ResourceAccessGateHandler gateHandler = new ResourceAccessGateHandler(gateRef, gate);
        Assert.assertTrue(gateHandler.matches("/content", Operation.READ));
        Assert.assertFalse(gateHandler.matches("/content", Operation.EXECUTE));
        Assert.assertTrue(gateHandler.isFinalOperation(Operation.READ));
        Assert.assertFalse(gateHandler.isFinalOperation(Operation.EXECUTE));
    }
    
    @Test
    public void testMultiValueProperties() {
        Mockito.when(gateRef.getProperty(ResourceAccessGate.PATH)).thenReturn("/content");
        Mockito.when(gateRef.getProperty(ResourceAccessGate.OPERATIONS)).thenReturn(new String[]{"read", "update", "invalid"});
        Mockito.when(gateRef.getProperty(ResourceAccessGate.FINALOPERATIONS)).thenReturn(new String[]{"read", "update", "invalid"});
        ResourceAccessGateHandler gateHandler = new ResourceAccessGateHandler(gateRef, gate);
        Assert.assertTrue(gateHandler.matches("/content", Operation.READ));
        Assert.assertFalse(gateHandler.matches("/othercontent", Operation.READ));
        Assert.assertTrue(gateHandler.matches("/content", Operation.UPDATE));
        Assert.assertFalse(gateHandler.matches("/content", Operation.EXECUTE));
        Assert.assertTrue(gateHandler.isFinalOperation(Operation.READ));
        Assert.assertTrue(gateHandler.isFinalOperation(Operation.UPDATE));
    }

    @Test
    public void testDefaultOperationsAndPath() {
        Mockito.when(gateRef.getProperty(ResourceAccessGate.OPERATIONS)).thenReturn(new String[] {});
        ResourceAccessGateHandler gateHandler = new ResourceAccessGateHandler(gateRef, gate);
        Assert.assertTrue(gateHandler.matches("/content1", Operation.READ));
        Assert.assertTrue(gateHandler.matches(null, Operation.READ));
        Assert.assertTrue(gateHandler.matches("/content2", Operation.CREATE));
        Assert.assertTrue(gateHandler.matches(null, Operation.CREATE));
        Assert.assertTrue(gateHandler.matches("/content3", Operation.EXECUTE));
        Assert.assertTrue(gateHandler.matches(null, Operation.EXECUTE));
        Assert.assertTrue(gateHandler.matches("/content4", Operation.ORDER_CHILDREN));
        Assert.assertTrue(gateHandler.matches(null, Operation.ORDER_CHILDREN));
        Assert.assertTrue(gateHandler.matches("/content5", Operation.UPDATE));
        Assert.assertTrue(gateHandler.matches(null, Operation.UPDATE));
    }
}
