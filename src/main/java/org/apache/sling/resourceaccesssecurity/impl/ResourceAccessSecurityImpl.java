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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.security.AccessSecurityException;
import org.apache.sling.api.security.ResourceAccessSecurity;
import org.apache.sling.resourceaccesssecurity.ResourceAccessGate;
import org.apache.sling.resourceaccesssecurity.ResourceAccessGate.GateResult;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.ComponentContext;

public abstract class ResourceAccessSecurityImpl implements ResourceAccessSecurity {

    private List<ResourceAccessGateHandler> allHandlers = Collections.emptyList();

    private final boolean defaultAllowIfNoGateMatches;

    protected ResourceAccessSecurityImpl(final boolean defaultAllowIfNoGateMatches, List<ServiceReference<ResourceAccessGate>> resourceAccessGateRefs,
            ComponentContext componentContext, String resourceAccessGateReferenceName) {
        this.defaultAllowIfNoGateMatches = defaultAllowIfNoGateMatches;
        // sort from highest ranked service to lowest ranked (opposite of default sorting of ServiceReference)
        this.allHandlers = resourceAccessGateRefs.stream().sorted(Collections.reverseOrder()).map(ref -> new ResourceAccessGateHandler(ref, componentContext.locateService(resourceAccessGateReferenceName, ref))).collect(Collectors.toList());
    }


    /**
     * This method returns either an iterator delivering the matching handlers
     * or <code>null</code>.
     */
    private Iterator<ResourceAccessGateHandler> getMatchingResourceAccessGateHandlerIterator(
            final String path, final ResourceAccessGate.Operation operation) {
        //
        // TODO: maybe caching some frequent paths with read operation would be
        // a good idea
        //
        final List<ResourceAccessGateHandler> handlers = allHandlers;
        if (!handlers.isEmpty()) {

            final Iterator<ResourceAccessGateHandler> iter = handlers.iterator();
            return new Iterator<ResourceAccessGateHandler>() {

                private ResourceAccessGateHandler next;

                {
                    peek();
                }

                private void peek() {
                    this.next = null;
                    while ( iter.hasNext() && next == null ) {
                        final ResourceAccessGateHandler handler = iter.next();
                        if (handler.matches(path, operation)) {
                            next = handler;
                        }
                    }
                }

                @Override
                public boolean hasNext() {
                    return next != null;
                }

                @Override
                public ResourceAccessGateHandler next() {
                    if ( next == null ) {
                        throw new NoSuchElementException();
                    }
                    final ResourceAccessGateHandler handler = this.next;
                    peek();
                    return handler;
                }

                @Override
                public void remove() {
                    throw new UnsupportedOperationException();
                }
            };
        }

        return null;
    }

    @Override
    public Resource getReadableResource(final Resource resource) {
        Resource returnValue = null;

        final Iterator<ResourceAccessGateHandler> accessGateHandlers = getMatchingResourceAccessGateHandlerIterator(
                resource.getPath(), ResourceAccessGate.Operation.READ);

        GateResult finalGateResult = null;
        List<ResourceAccessGate> accessGatesForReadValues = null;
        boolean canReadAllValues = false;


        if ( accessGateHandlers != null ) {

            boolean noGateMatched = true;
            
            while ( accessGateHandlers.hasNext() ) {
                noGateMatched = false;
                final ResourceAccessGateHandler resourceAccessGateHandler  = accessGateHandlers.next();

                final GateResult gateResult = !resourceAccessGateHandler
                        .getResourceAccessGate().hasReadRestrictions(resource.getResourceResolver()) ? GateResult.GRANTED
                        : resourceAccessGateHandler.getResourceAccessGate()
                                .canRead(resource);
                if (!canReadAllValues && gateResult == GateResult.GRANTED) {
                    if (resourceAccessGateHandler.getResourceAccessGate().canReadAllValues(resource)) {
                        canReadAllValues = true;
                        accessGatesForReadValues = null;
                    } else {
                        if (accessGatesForReadValues == null) {
                            accessGatesForReadValues = new ArrayList<>();
                        }
                        accessGatesForReadValues.add(resourceAccessGateHandler.getResourceAccessGate());
                    }
                }
                if (finalGateResult == null || finalGateResult == GateResult.DENIED) {
                    finalGateResult = gateResult;
                }
                // stop checking if the operation is final and the result not GateResult.CANT_DECIDE
                if (gateResult != GateResult.CANT_DECIDE  && resourceAccessGateHandler.isFinalOperation(ResourceAccessGate.Operation.READ)) {
                    break;
                }
            }


            // return null if access is denied or no ResourceAccessGate is present
            if (finalGateResult == GateResult.DENIED) {
                returnValue = null;
            } else if (finalGateResult == GateResult.GRANTED ) {
                returnValue = resource;
            } else if (noGateMatched && this.defaultAllowIfNoGateMatches)
            {
                returnValue = resource;
            }
        }

        boolean canUpdateResource = canUpdate(resource);

        // wrap Resource if read access is not or partly (values) not granted
        if (returnValue != null) {
            if( !canReadAllValues || !canUpdateResource ) {
                returnValue = new AccessGateResourceWrapper(returnValue,
                        accessGatesForReadValues,
                        canUpdateResource);
            }
        }

        return returnValue;
    }

    private boolean canDoOperation(ResourceAccessGate.Operation operation, String path, Predicate<ResourceAccessGate> gatePredicate, Function<ResourceAccessGate, GateResult> gateResultFilter) {
        final Iterator<ResourceAccessGateHandler> handlers = getMatchingResourceAccessGateHandlerIterator(
                path, operation);
        boolean result = false;
        if ( handlers != null ) {
            GateResult finalGateResult = null;
            boolean noGateMatched = true;

            while ( handlers.hasNext() ) {
                noGateMatched = false;
                final ResourceAccessGateHandler resourceAccessGateHandler  = handlers.next();

                final GateResult gateResult = !gatePredicate.test(resourceAccessGateHandler.getResourceAccessGate()) ? GateResult.GRANTED
                        : gateResultFilter.apply(resourceAccessGateHandler.getResourceAccessGate());
                if (finalGateResult == null || finalGateResult == GateResult.DENIED) {
                    finalGateResult = gateResult;
                }
                if (finalGateResult == GateResult.GRANTED || gateResult != GateResult.CANT_DECIDE && 
                        resourceAccessGateHandler.isFinalOperation(operation)) {
                    break;
                }
            }

            if ( finalGateResult == GateResult.GRANTED || (noGateMatched && this.defaultAllowIfNoGateMatches)) {
                result = true;
            }
        }
        return result;
    }
    
    
    @Override
    public boolean canOrderChildren(Resource resource) {
        return canDoOperation(ResourceAccessGate.Operation.ORDER_CHILDREN, resource.getPath(), gate -> gate.hasOrderChildrenRestrictions(resource.getResourceResolver()), gate -> gate.canOrderChildren(resource));
    }

    @Override
    public boolean canCreate(final String path, final ResourceResolver resolver) {
        return canDoOperation(ResourceAccessGate.Operation.CREATE, path, gate -> gate.hasCreateRestrictions(resolver), gate -> gate.canCreate(path, resolver));
    }

    @Override
    public boolean canUpdate(final Resource resource) {
        return canDoOperation(ResourceAccessGate.Operation.UPDATE, resource.getPath(), gate -> gate.hasUpdateRestrictions(resource.getResourceResolver()), gate -> gate.canUpdate(resource));
    }

    @Override
    public boolean canDelete(final Resource resource) {
        return canDoOperation(ResourceAccessGate.Operation.DELETE, resource.getPath(), gate -> gate.hasDeleteRestrictions(resource.getResourceResolver()), gate -> gate.canDelete(resource));
    }

    @Override
    public boolean canExecute(final Resource resource) {
        return canDoOperation(ResourceAccessGate.Operation.EXECUTE, resource.getPath(), gate -> gate.hasExecuteRestrictions(resource.getResourceResolver()), gate -> gate.canExecute(resource));
    }

    @Override
    public boolean canReadValue(final Resource resource, final String valueName) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean canSetValue(final Resource resource, final String valueName) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean canDeleteValue(final Resource resource, final String valueName) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public String transformQuery(final String query,
            final String language,
            final ResourceResolver resourceResolver)
    throws AccessSecurityException {
        String returnValue = query;

        for (ResourceAccessGateHandler handler : allHandlers) {
            returnValue = handler.getResourceAccessGate().transformQuery(
                    returnValue, language, resourceResolver);
            if (returnValue == null) {
                throw new AccessSecurityException(
                        "Method transformQuery in ResourceAccessGate "
                                + handler.getResourceAccessGate().getClass()
                                        .getName() + " returned null.");
            }
        }

        return returnValue;
    }
}
