/*******************************************************************************
 * Copyright (c) 2020, 2022 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.authorization.util;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

public class RoleMethodAuthUtil {
    private static final Logger LOG = Logger.getLogger(RoleMethodAuthUtil.class.getName());

    private static final ConcurrentHashMap<MethodAnnotationsKey, MethodAnnotations> annotations = new ConcurrentHashMap<>();

    private static final ReferenceQueue<Class<?>> referenceQueue = new ReferenceQueue<>();

    private static class MethodAnnotations {
        private Boolean denyAll;
        private Boolean permitAll;
        private RolesAllowed rolesAllowed;

        public Boolean getDenyAll() {
            return denyAll;
        }

        public void setDenyAll(Boolean denyAll) {
            this.denyAll = denyAll;
        }

        public Boolean getPermitAll() {
            return permitAll;
        }

        public void setPermitAll(Boolean permitAll) {
            this.permitAll = permitAll;
        }

        public RolesAllowed getRolesAllowed() {
            return rolesAllowed;
        }

        public void setRolesAllowed(RolesAllowed rolesAllowed) {
            this.rolesAllowed = rolesAllowed;
        }
    }

    @SuppressWarnings("unchecked")
    private static void poll() {
        MethodAnnotationsKeyWeakReference<Class<?>> key;
        while ((key = (MethodAnnotationsKeyWeakReference<Class<?>>) referenceQueue.poll()) != null) {
            annotations.remove(key.getOwningKey());
        }
    }

    private static MethodAnnotations getMethodAnnotations(Class<?> declaringClass, Method method) {
        poll();
        return annotations.get(new MethodAnnotationsKey(declaringClass, method));
    }

    /**
     * Add a new route for the specified REST Class and Method.
     *
     * @param restClass
     * @param restMethod
     * @param route
     */
    private static void putMethodAnnotations(Class<?> declaringClass, Method method, MethodAnnotations methodAnnotations) {
        poll();
        annotations.put(new MethodAnnotationsKey(referenceQueue, declaringClass, method), methodAnnotations);
    }

    private static class MethodAnnotationsKey {
        private final MethodAnnotationsKeyWeakReference<Class<?>> restClassRef;
        private final MethodAnnotationsKeyWeakReference<Method> restMethodRef;
        private final int hash;

        MethodAnnotationsKey(Class<?> declaringClass, Method method) {
            this.restClassRef = new MethodAnnotationsKeyWeakReference<>(declaringClass, this);
            this.restMethodRef = new MethodAnnotationsKeyWeakReference<>(method, this);
            hash = (17 * 31 + declaringClass.hashCode()) * 31 + method.hashCode();
        }

        MethodAnnotationsKey(ReferenceQueue<Class<?>> referenceQueue, Class<?> declaringClass, Method method) {
            this.restClassRef = new MethodAnnotationsKeyWeakReference<>(declaringClass, this, referenceQueue);
            this.restMethodRef = new MethodAnnotationsKeyWeakReference<>(method, this);
            hash = (17 * 31 + declaringClass.hashCode()) * 31 + method.hashCode();
        }

        @Override
        public int hashCode() {
            return hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            MethodAnnotationsKey other = (MethodAnnotationsKey) obj;
            if (!restClassRef.equals(other.restClassRef)) {
                return false;
            }
            if (!restMethodRef.equals(other.restMethodRef)) {
                return false;
            }
            return true;
        }
    }

    private static class MethodAnnotationsKeyWeakReference<T> extends WeakReference<T> {
        private final MethodAnnotationsKey owningKey;

        MethodAnnotationsKeyWeakReference(T referent, MethodAnnotationsKey owningKey) {
            super(referent);
            this.owningKey = owningKey;
        }

        MethodAnnotationsKeyWeakReference(T referent, MethodAnnotationsKey owningKey,
                                          ReferenceQueue<T> referenceQueue) {

            super(referent, referenceQueue);
            this.owningKey = owningKey;
        }

        MethodAnnotationsKey getOwningKey() {
            return owningKey;
        }

        @SuppressWarnings("rawtypes")
        @Override
        public boolean equals(Object obj) {

            if (obj == this) {
                return true;
            }

            if (obj instanceof MethodAnnotationsKeyWeakReference) {
                return get() == ((MethodAnnotationsKeyWeakReference) obj).get();
            }

            return false;
        }

        @Override
        public String toString() {
            T referent = get();
            return new StringBuilder("MethodAnnotationsKeyWeakReference: ").append(referent).toString();
        }
    }

    public static void checkAuthentication(Principal principal) throws UnauthenticatedException {
        if (principal == null) {
            throw new UnauthenticatedException("principal is null");
        }
        if ("UNAUTHENTICATED".equals(principal.getName())) {
            throw new UnauthenticatedException("principal is UNAUTHENTICATED");
        }
    }

    public static boolean parseMethodSecurity(Method method, Supplier<Principal> principal, Predicate<String> isUserInRoleFunction) throws UnauthenticatedException {

        Class<?> declaringClass = method.getDeclaringClass();
        MethodAnnotations methodAnnotations = getMethodAnnotations(declaringClass, method);

        if (methodAnnotations == null) {
            methodAnnotations = new MethodAnnotations();
            methodAnnotations.setDenyAll(getDenyAll(method));
            methodAnnotations.setPermitAll(getPermitAll(method));
            methodAnnotations.setRolesAllowed(getRolesAllowed(method));
            putMethodAnnotations(declaringClass, method, methodAnnotations);
        }

        if (methodAnnotations.getDenyAll()) {
            if (LOG.isLoggable(Level.FINEST)) {
                LOG.finest("Found DenyAll for method: {} " + method.getName()
                           + ", Injection Processing for web service is ignored");
            }
            return false;

        } else { // try RolesAllowed
            RolesAllowed rolesAllowed = methodAnnotations.getRolesAllowed();
            if (rolesAllowed != null) {
                String[] theseroles = rolesAllowed.value();
                if (LOG.isLoggable(Level.FINEST)) {
                    LOG.log(Level.FINEST, "found RolesAllowed in method: {} " + method.getName(),
                            new Object[] { theseroles });
                }
                for (String role : theseroles) {
                    if (isUserInRoleFunction.test(role)) {
                        return true;
                    }
                }
                checkAuthentication(principal.get()); // throws UnauthenticatedException if not authenticated
                return false; // authenticated, but not authorized
            } else {
                if (methodAnnotations.getPermitAll()) {
                    if (LOG.isLoggable(Level.FINEST)) {
                        LOG.finest("Found PermitAll for method: {}" + method.getName());
                    }
                    return true;
                } else { // try class level annotations
                    Class<?> cls = method.getDeclaringClass();
                    return parseClassSecurity(cls, principal, isUserInRoleFunction);
                }
            }
        }
    }

    // parse security JSR250 annotations at the class level
    private static boolean parseClassSecurity(Class<?> cls, Supplier<Principal> principal, Predicate<String> isUserInRoleFunction) throws UnauthenticatedException {

        // try DenyAll
        DenyAll denyAll = cls.getAnnotation(DenyAll.class);
        if (denyAll != null) {
            if (LOG.isLoggable(Level.FINEST)) {
                LOG.finest("Found class level @DenyAll - authorization denied for " + cls.getName());
            }
            return false;
        } else { // try RolesAllowed

            RolesAllowed rolesAllowed = cls.getAnnotation(RolesAllowed.class);
            if (rolesAllowed != null) {
                String[] theseroles = rolesAllowed.value();
                if (LOG.isLoggable(Level.FINEST)) {
                    LOG.log(Level.FINEST, "found RolesAllowed in class: {} " + cls.getName(),
                            new Object[] { theseroles });
                }
                for (String role : theseroles) {
                    if (isUserInRoleFunction.test(role)) {
                        return true;
                    }
                }
                checkAuthentication(principal.get()); // throws UnauthenticatedException if not authenticated
                return false; // authenticated, but not authorized
            } else {
                // if no annotations on method or class (or if class has @PermitAll), return true;
                return true;
            }
        }
    }

    private static RolesAllowed getRolesAllowed(Method method) {
        return method.getAnnotation(RolesAllowed.class);
    }

    private static boolean getPermitAll(Method method) {
        return method.isAnnotationPresent(PermitAll.class);
    }

    private static boolean getDenyAll(Method method) {
        return method.isAnnotationPresent(DenyAll.class);
    }
}
