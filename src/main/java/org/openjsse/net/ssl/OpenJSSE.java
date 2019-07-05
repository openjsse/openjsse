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

package org.openjsse.net.ssl;

/**
 * Main class for the OpenJSSE provider. The actual code was moved to the
 * class sun.security.ssl.OpenJSSE, but for backward compatibility we
 * continue to use this class as the main Provider class.
 */
public final class OpenJSSE extends org.openjsse.sun.security.ssl.OpenJSSE {

    private static final long serialVersionUID = 3231825739635378733L;

    // standard constructor
    public OpenJSSE() {
        super();
    }

    // preferred constructor to enable FIPS mode at runtime
    public OpenJSSE(java.security.Provider cryptoProvider) {
        super(cryptoProvider);
    }

    // constructor to enable FIPS mode from java.security file
    public OpenJSSE(String cryptoProvider) {
        super(cryptoProvider);
    }

    // public for now, but we may want to change it or not document it.
    public static synchronized boolean isFIPS() {
        return org.openjsse.sun.security.ssl.OpenJSSE.isFIPS();
    }

    /**
     * Installs the JSSE provider.
     */
    public static synchronized void install() {
        /* nop. Remove this method in the future. */
    }

}
