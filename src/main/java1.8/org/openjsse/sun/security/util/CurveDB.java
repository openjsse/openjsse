/*
 * Copyright 2019 Azul Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package org.openjsse.sun.security.util;

import java.security.spec.ECParameterSpec;
import java.lang.reflect.*;
import java.security.*;
import java.util.Optional;

/**
 * Wrapper class for sun.security.ec.CurveDB.lookup methods 
 */
public class CurveDB {
    private static Optional<Method> lookupByName = null;
    private static Optional<Method> lookupByParam = null;
    private static Object lookupByNameLock = new Object();
    private static Object lookupByParamLock = new Object();

    private static void makeAccessible(final AccessibleObject o) {
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                o.setAccessible(true);
                return null;
            }
        });
    }

    // Return a NamedCurve for the specified OID/name or null if unknown.
    public static ECParameterSpec lookup(String name) {
    	synchronized(lookupByNameLock) {
	    	if (lookupByName == null) {
	    		try {
	    			Class clazz = Class.forName("sun.security.ec.CurveDB");
	    			lookupByName = Optional.ofNullable( clazz.getDeclaredMethod("lookup", String.class));
	    			makeAccessible(lookupByName.get());
	    		} catch(ClassNotFoundException | NoSuchMethodException | SecurityException e) {
	    			lookupByName = Optional.empty();
	    		}
	    	}
	    }
	    if (lookupByName.isPresent())
	    	try {
	    		return (ECParameterSpec)lookupByName.get().invoke(null, name);
	    	} catch(IllegalAccessException | InvocationTargetException e){};
        return null;
    }
    // Convert the given ECParameterSpec object to a NamedCurve object.
    // If params does not represent a known named curve, return null.
    public static ECParameterSpec lookup(ECParameterSpec params) {
    	synchronized(lookupByParamLock) {
	    	if (lookupByParam == null) {
	    		try {
	    			Class clazz = Class.forName("sun.security.ec.CurveDB");
	    			lookupByParam = Optional.ofNullable( clazz.getDeclaredMethod("lookup", ECParameterSpec.class));
	    			makeAccessible(lookupByParam.get());
	    		} catch(ClassNotFoundException | NoSuchMethodException | SecurityException e) {
	    			lookupByParam = Optional.empty();
	    		}
	    	}
	    }
	    if (lookupByParam.isPresent())
	    	try {
	    		return (ECParameterSpec)lookupByParam.get().invoke(null, params);
	    	} catch(IllegalAccessException | InvocationTargetException e){};
        return null;
    }
}
