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


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Arrays;

import org.apache.sling.api.resource.ModifiableValueMap;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ValueMap;
import org.apache.sling.api.security.ResourceAccessSecurity;
import org.apache.sling.resourceaccesssecurity.ResourceAccessGate;
import org.junit.Test;
import org.mockito.Mockito;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.ComponentContext;
import static org.junit.Assert.fail;

public class ResourceAccessSecurityImplTests {

    ServiceReference<ResourceAccessGate> serviceReference;
    ResourceAccessSecurity resourceAccessSecurity;
    ResourceAccessGate resourceAccessGate;


    @Test
    public void testInitWithMultipleGates() {

        ServiceReference<ResourceAccessGate> serviceReference = mock(ServiceReference.class);
        ResourceAccessGate resourceAccessGate = mock(ResourceAccessGate.class);

        ServiceReference<ResourceAccessGate> serviceReference2 = mock(ServiceReference.class);
        ResourceAccessGate resourceAccessGate2 = mock(ResourceAccessGate.class);

        // Mock the service references to have different rankings
        when(serviceReference.compareTo(serviceReference2)).thenReturn(-1);
        when(serviceReference2.compareTo(serviceReference)).thenReturn(1);

        ComponentContext context = mock(ComponentContext.class);
        when(context.locateService(Mockito.anyString(), Mockito.eq(serviceReference))).thenReturn(resourceAccessGate);
        when(context.locateService(Mockito.anyString(), Mockito.eq(serviceReference2))).thenReturn(resourceAccessGate2);

        try {
            resourceAccessSecurity = new ProviderResourceAccessSecurityImpl(
                Arrays.asList(serviceReference, serviceReference2),
                context);

            // Verify that the gates are sorted in reverse order
            verify(serviceReference).compareTo(serviceReference2);
        } catch (Exception e) {
            fail("Should not throw exception: " + e.getMessage());
        }
    }

    @Test
    public void testCanUpdate(){
        initMocks("/content", new String[] { "update"} );

        Resource resource = mock(Resource.class);
        when(resource.getPath()).thenReturn("/content");
        when(resourceAccessGate.canUpdate(resource)).thenReturn(ResourceAccessGate.GateResult.GRANTED);
        assertTrue(resourceAccessSecurity.canUpdate(resource));
    }

    @Test
    public void testCannotUpdate(){
        initMocks("/content", new String[] { "update"} );

        Resource resource = mock(Resource.class);
        when(resource.getPath()).thenReturn("/content");
        when(resourceAccessGate.canUpdate(resource)).thenReturn(ResourceAccessGate.GateResult.DENIED);
        assertFalse(resourceAccessSecurity.canUpdate(resource));
    }

    @Test
    public void testCannotUpdateWrongPath(){
        initMocks("/content", new String[] { "update"} );

        Resource resource = mock(Resource.class);
        when(resource.getPath()).thenReturn("/wrongcontent");
        when(resourceAccessGate.canUpdate(resource)).thenReturn(ResourceAccessGate.GateResult.GRANTED);
        assertFalse(resourceAccessSecurity.canUpdate(resource));
    }

    @Test
    public void testCanUpdateUsingReadableResource(){
        // one needs to have also read rights to obtain the resource

        initMocks("/content", new String[] { "read", "update"} );

        Resource resource = mock(Resource.class);
        when(resource.getPath()).thenReturn("/content");

        ModifiableValueMap valueMap = mock(ModifiableValueMap.class);
        when(resource.adaptTo(ModifiableValueMap.class)).thenReturn(valueMap);

        when(resourceAccessGate.canRead(resource)).thenReturn(ResourceAccessGate.GateResult.GRANTED);
        when(resourceAccessGate.canUpdate(resource)).thenReturn(ResourceAccessGate.GateResult.GRANTED);
        Resource readableResource = resourceAccessSecurity.getReadableResource(resource);

        ModifiableValueMap resultValueMap = readableResource.adaptTo(ModifiableValueMap.class);


        resultValueMap.put("modified", "value");

        verify(valueMap, times(1)).put("modified", "value");
    }


    @Test
    public void testCannotUpdateUsingReadableResourceIfCannotRead(){
        initMocks("/content", new String[] { "read", "update"} );

        Resource resource = mock(Resource.class);
        when(resource.getPath()).thenReturn("/content");

        ModifiableValueMap valueMap = mock(ModifiableValueMap.class);
        when(resource.adaptTo(ModifiableValueMap.class)).thenReturn(valueMap);

        when(resourceAccessGate.canRead(resource)).thenReturn(ResourceAccessGate.GateResult.DENIED);
        when(resourceAccessGate.canUpdate(resource)).thenReturn(ResourceAccessGate.GateResult.GRANTED);
        Resource readableResource = resourceAccessSecurity.getReadableResource(resource);


        assertNull(readableResource);
    }


    @Test
    public void testCannotUpdateUsingReadableResourceIfCannotUpdate(){
        initMocks("/content", new String[] { "read", "update"} );

        Resource resource = mock(Resource.class);
        when(resource.getPath()).thenReturn("/content");

        ModifiableValueMap valueMap = mock(ModifiableValueMap.class);
        when(resource.adaptTo(ModifiableValueMap.class)).thenReturn(valueMap);

        when(resourceAccessGate.canRead(resource)).thenReturn(ResourceAccessGate.GateResult.GRANTED);
        when(resourceAccessGate.canUpdate(resource)).thenReturn(ResourceAccessGate.GateResult.DENIED);
        Resource readableResource = resourceAccessSecurity.getReadableResource(resource);

        ModifiableValueMap resultValueMap = readableResource.adaptTo(ModifiableValueMap.class);

        assertNull(resultValueMap);
    }


    @Test
    public void testCannotUpdateAccidentallyUsingReadableResourceIfCannotUpdate(){
        initMocks("/content", new String[] { "read", "update"} );

        Resource resource = mock(Resource.class);
        when(resource.getPath()).thenReturn("/content");

        ModifiableValueMap valueMap = mock(ModifiableValueMap.class);
        when(resource.adaptTo(ValueMap.class)).thenReturn(valueMap);

        when(resourceAccessGate.canRead(resource)).thenReturn(ResourceAccessGate.GateResult.GRANTED);
        when(resourceAccessGate.canUpdate(resource)).thenReturn(ResourceAccessGate.GateResult.DENIED);
        Resource readableResource = resourceAccessSecurity.getReadableResource(resource);

        ValueMap resultValueMap = readableResource.adaptTo(ValueMap.class);

        resultValueMap.put("modified", "value");

        verify(valueMap, times(0)).put("modified", "value");
    }

    @Test
    public void testCanOrderChildren() {
        initMocks("/content", new String[] { "order-children" } );

        Resource resource = mock(Resource.class);
        when(resource.getPath()).thenReturn("/content");
        when(resourceAccessGate.canOrderChildren(resource)).thenReturn(ResourceAccessGate.GateResult.GRANTED);
        assertTrue(resourceAccessSecurity.canOrderChildren(resource));
    }

    @Test
    public void testCannotOrderChildren() {
        initMocks("/content", new String[] { "order-children" } );

        Resource resource = mock(Resource.class);
        when(resource.getPath()).thenReturn("/content");
        when(resourceAccessGate.canOrderChildren(resource)).thenReturn(ResourceAccessGate.GateResult.DENIED);
        assertFalse(resourceAccessSecurity.canOrderChildren(resource));
    }

    private void initMocks(String path, String[] operations){
        serviceReference = mock(ServiceReference.class);
        resourceAccessGate = mock(ResourceAccessGate.class);

        when(resourceAccessGate.hasReadRestrictions(Mockito.any())).thenReturn(true);
        when(resourceAccessGate.hasCreateRestrictions(Mockito.any())).thenReturn(true);
        when(resourceAccessGate.hasUpdateRestrictions(Mockito.any())).thenReturn(true);
        when(resourceAccessGate.hasOrderChildrenRestrictions(Mockito.any())).thenReturn(true);

        when(serviceReference.getProperty(ResourceAccessGate.PATH)).thenReturn(path);
        when(serviceReference.getProperty(ResourceAccessGate.OPERATIONS)).thenReturn(operations);

        ComponentContext context = mock(ComponentContext.class);
        when(context.locateService(Mockito.anyString(), Mockito.eq(serviceReference))).thenReturn(resourceAccessGate);
        resourceAccessSecurity = new ProviderResourceAccessSecurityImpl(Collections.singletonList(serviceReference), context);
    }

}
