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

import java.util.List;

import org.apache.sling.api.security.ResourceAccessSecurity;
import org.apache.sling.resourceaccesssecurity.ResourceAccessGate;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicyOption;

@Component(
        service = ResourceAccessSecurity.class,
        property = ResourceAccessSecurity.CONTEXT + "=" + ResourceAccessSecurity.PROVIDER_CONTEXT)
public class ProviderResourceAccessSecurityImpl extends ResourceAccessSecurityImpl {

    private static final String RESOURCE_ACCESS_GATE_REFERENCE_NAME = "resourceAccessGates";

    @Activate
    public ProviderResourceAccessSecurityImpl(
            @Reference(
                            name = RESOURCE_ACCESS_GATE_REFERENCE_NAME,
                            cardinality = ReferenceCardinality.AT_LEAST_ONE,
                            policyOption = ReferencePolicyOption.GREEDY,
                            target = "(" + ResourceAccessGate.CONTEXT + "=" + ResourceAccessGate.PROVIDER_CONTEXT + ")")
                    List<ServiceReference<ResourceAccessGate>> resourceAccessGates,
            ComponentContext componentContext) {
        super(false, resourceAccessGates, componentContext, RESOURCE_ACCESS_GATE_REFERENCE_NAME);
    }
}
