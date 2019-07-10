/*
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
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

package org.openjsse.javax.net.ssl;

import java.util.List;
import javax.net.ssl.*;

/**
 * Extends the {@code SSLSession} interface to support additional
 * session attributes.
 */
public abstract class ExtendedSSLSession extends javax.net.ssl.ExtendedSSLSession {

    /**
     * Returns a {@link List} containing DER-encoded OCSP responses
     * (using the ASN.1 type OCSPResponse defined in RFC 6960) for
     * the client to verify status of the server's certificate during
     * handshaking.
     *
     * <P>
     * This method only applies to certificate-based server
     * authentication.  An {@link X509ExtendedTrustManager} will use the
     * returned value for server certificate validation.
     *
     * @implSpec This method throws UnsupportedOperationException by default.
     *         Classes derived from ExtendedSSLSession must implement
     *         this method.
     *
     * @return a non-null unmodifiable list of byte arrays, each entry
     *         containing a DER-encoded OCSP response (using the
     *         ASN.1 type OCSPResponse defined in RFC 6960).  The order
     *         of the responses must match the order of the certificates
     *         presented by the server in its Certificate message (See
     *         {@link SSLSession#getLocalCertificates()} for server mode,
     *         and {@link SSLSession#getPeerCertificates()} for client mode).
     *         It is possible that fewer response entries may be returned than
     *         the number of presented certificates.  If an entry in the list
     *         is a zero-length byte array, it should be treated by the
     *         caller as if the OCSP entry for the corresponding certificate
     *         is missing.  The returned list may be empty if no OCSP responses
     *         were presented during handshaking or if OCSP stapling is not
     *         supported by either endpoint for this handshake.
     *
     * @throws UnsupportedOperationException if the underlying provider
     *         does not implement the operation
     *
     * @see X509ExtendedTrustManager
     *
     * @since 9
     */
    public List<byte[]> getStatusResponses() {
        throw new UnsupportedOperationException();
    }
}
