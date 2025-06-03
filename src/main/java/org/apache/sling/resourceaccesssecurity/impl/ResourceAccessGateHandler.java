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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.sling.commons.osgi.PropertiesUtil;
import org.apache.sling.resourceaccesssecurity.ResourceAccessGate;
import org.jetbrains.annotations.NotNull;
import org.osgi.framework.ServiceReference;

public class ResourceAccessGateHandler {

    private final @NotNull ResourceAccessGate resourceAccessGate;

    private final @NotNull ServiceReference<ResourceAccessGate> reference;

    private final @NotNull Pattern pathPattern;
    private final Set<ResourceAccessGate.Operation> operations = new HashSet<>();
    private final Set<ResourceAccessGate.Operation> finalOperations = new HashSet<>();

    /**
     * constructor
     */
    public ResourceAccessGateHandler(
            @NotNull final ServiceReference<ResourceAccessGate> resourceAccessGateRef,
            @NotNull final ResourceAccessGate resourceAccessGate) {
        this.reference = resourceAccessGateRef;
        this.resourceAccessGate = resourceAccessGate;
        // extract the service property "path"
        final String path = (String) resourceAccessGateRef.getProperty(ResourceAccessGate.PATH);
        if (path != null) {
            pathPattern = Pattern.compile(path);
        } else {
            pathPattern = Pattern.compile(".*");
        }

        // extract the service property "operations"
        final String[] ops =
                PropertiesUtil.toStringArray(resourceAccessGateRef.getProperty(ResourceAccessGate.OPERATIONS));
        if (ops != null && ops.length > 0) {
            for (final String opAsString : ops) {
                final ResourceAccessGate.Operation operation = ResourceAccessGate.Operation.fromString(opAsString);
                if (operation != null) {
                    operations.add(operation);
                }
            }
        } else {
            Collections.addAll(operations, ResourceAccessGate.Operation.values());
        }

        // extract the service property "finaloperations"
        final String[] finalOps =
                PropertiesUtil.toStringArray(resourceAccessGateRef.getProperty(ResourceAccessGate.FINALOPERATIONS));
        if (finalOps != null) {
            for (final String opAsString : finalOps) {
                final ResourceAccessGate.Operation operation = ResourceAccessGate.Operation.fromString(opAsString);
                if (operation != null) {
                    finalOperations.add(operation);
                }
            }
        }
    }

    public boolean matches(final String path, final ResourceAccessGate.Operation operation) {
        boolean returnValue = false;

        if (operations.contains(operation)) {
            if (path != null) {
                final Matcher match = pathPattern.matcher(path);
                returnValue = match.matches();
            } else {
                // if no path is given just add every ResourceAccessGate for
                // security reason
                return true;
            }
        }

        return returnValue;
    }

    public boolean isFinalOperation(final ResourceAccessGate.Operation operation) {
        return finalOperations.contains(operation);
    }

    public @NotNull ResourceAccessGate getResourceAccessGate() {
        return resourceAccessGate;
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj instanceof ResourceAccessGateHandler) {
            return ((ResourceAccessGateHandler) obj).reference.equals(this.reference);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return this.reference.hashCode();
    }
}
