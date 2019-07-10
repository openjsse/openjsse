/*
 * Copyright (c) 1999, 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

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

package org.openjsse.sun.security.ssl;

import java.util.List;
import java.util.Collections;

import java.security.*;
import java.security.KeyStore.*;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.KeyStoreBuilderParameters;

abstract class KeyManagerFactoryImpl extends KeyManagerFactorySpi {

    X509ExtendedKeyManager keyManager;
    boolean isInitialized;

    KeyManagerFactoryImpl() {
        // empty
    }

    /**
     * Returns one key manager for each type of key material.
     */
    @Override
    protected KeyManager[] engineGetKeyManagers() {
        if (!isInitialized) {
            throw new IllegalStateException(
                        "KeyManagerFactoryImpl is not initialized");
        }
        return new KeyManager[] { keyManager };
    }

    // Factory for the SunX509 keymanager
    public static final class SunX509 extends KeyManagerFactoryImpl {

        @Override
        protected void engineInit(KeyStore ks, char[] password) throws
                KeyStoreException, NoSuchAlgorithmException,
                UnrecoverableKeyException {
            if ((ks != null) && OpenJSSE.isFIPS()) {
                if (ks.getProvider() != OpenJSSE.cryptoProvider) {
                    throw new KeyStoreException("FIPS mode: KeyStore must be "
                        + "from provider " + OpenJSSE.cryptoProvider.getName());
                }
            }
            keyManager = new SunX509KeyManagerImpl(ks, password);
            isInitialized = true;
        }

        @Override
        protected void engineInit(ManagerFactoryParameters spec) throws
                InvalidAlgorithmParameterException {
            throw new InvalidAlgorithmParameterException(
                "SunX509KeyManager does not use ManagerFactoryParameters");
        }

    }

    // Factory for the X509 keymanager
    public static final class X509 extends KeyManagerFactoryImpl {

        @Override
        protected void engineInit(KeyStore ks, char[] password) throws
                KeyStoreException, NoSuchAlgorithmException,
                UnrecoverableKeyException {
            if (ks == null) {
                keyManager = new X509KeyManagerImpl(
                        Collections.<Builder>emptyList());
            } else {
                if (OpenJSSE.isFIPS() &&
                        (ks.getProvider() != OpenJSSE.cryptoProvider)) {
                    throw new KeyStoreException(
                        "FIPS mode: KeyStore must be " +
                        "from provider " + OpenJSSE.cryptoProvider.getName());
                }
                try {
                    Builder builder = Builder.newInstance(ks,
                        new PasswordProtection(password));
                    keyManager = new X509KeyManagerImpl(builder);
                } catch (RuntimeException e) {
                    throw new KeyStoreException("initialization failed", e);
                }
            }
            isInitialized = true;
        }

        @Override
        protected void engineInit(ManagerFactoryParameters params) throws
                InvalidAlgorithmParameterException {
            if (params instanceof KeyStoreBuilderParameters == false) {
                throw new InvalidAlgorithmParameterException(
                "Parameters must be instance of KeyStoreBuilderParameters");
            }
            if (OpenJSSE.isFIPS()) {
                throw new InvalidAlgorithmParameterException
                    ("FIPS mode: KeyStoreBuilderParameters not supported");
            }
            List<Builder> builders =
                ((KeyStoreBuilderParameters)params).getParameters();
            keyManager = new X509KeyManagerImpl(builders);
            isInitialized = true;
        }

    }

}
