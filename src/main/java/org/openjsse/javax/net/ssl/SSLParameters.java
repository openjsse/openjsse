/*
 * Copyright (c) 2005, 2017, Oracle and/or its affiliates. All rights reserved.
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

import java.security.AlgorithmConstraints;
import java.util.Map;
import java.util.List;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;

/**
 * Encapsulates parameters for an SSL/TLS/DTLS connection. The parameters
 * are the list of ciphersuites to be accepted in an SSL/TLS/DTLS handshake,
 * the list of protocols to be allowed, the endpoint identification
 * algorithm during SSL/TLS/DTLS handshaking, the Server Name Indication (SNI),
 * the maximum network packet size, the algorithm constraints and whether
 * SSL/TLS/DTLS servers should request or require client authentication, etc.
 * <p>
 * SSLParameters can be created via the constructors in this class.
 * Objects can also be obtained using the {@code getSSLParameters()}
 * methods in
 * {@link SSLSocket#getSSLParameters SSLSocket} and
 * {@link SSLEngine#getSSLParameters SSLEngine} or the
 * methods in {@code SSLContext}.
 * <p>
 * SSLParameters can be applied to a connection via the methods
 * {@link SSLSocket#setSSLParameters SSLSocket.setSSLParameters()} and
 * and {@link SSLEngine#setSSLParameters SSLEngine.setSSLParameters()}.
 * <p>
 * For example:
 *
 * <blockquote><pre>
 *     SSLParameters p = sslSocket.getSSLParameters();
 *     p.setProtocols(new String[] { "TLSv1.2" });
 *     p.setCipherSuites(
 *         new String[] { "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", ... });
 *     p.setApplicationProtocols(new String[] {"h2", "http/1.1"});
 *     sslSocket.setSSLParameters(p);
 * </pre></blockquote>
 *
 * @see SSLSocket
 * @see SSLEngine
 *
 */
public class SSLParameters extends javax.net.ssl.SSLParameters {

    private boolean enableRetransmissions = true;
    private int maximumPacketSize = 0;
    private String[] applicationProtocols = new String[0];

    /**
     * Constructs SSLParameters.
     * <p>
     * The values of cipherSuites, protocols, cryptographic algorithm
     * constraints, endpoint identification algorithm, server names and
     * server name matchers are set to {@code null}; useCipherSuitesOrder,
     * wantClientAuth and needClientAuth are set to {@code false};
     * enableRetransmissions is set to {@code true}; maximum network packet
     * size is set to {@code 0}.
     */
    public SSLParameters() {
        super();
    }

    /**
     * Constructs SSLParameters from the specified array of ciphersuites.
     * <p>
     * Calling this constructor is equivalent to calling the no-args
     * constructor followed by
     * {@code setCipherSuites(cipherSuites);}.  Note that the
     * standard list of cipher suite names may be found in the <a href=
     * "{@docRoot}/../specs/security/standard-names.html#jsse-cipher-suite-names">
     * JSSE Cipher Suite Names</a> section of the Java Cryptography
     * Architecture Standard Algorithm Name Documentation.  Providers
     * may support cipher suite names not found in this list.
     *
     * @param cipherSuites the array of ciphersuites (or null)
     */
    public SSLParameters(String[] cipherSuites) {
        super(cipherSuites);
    }

    /**
     * Constructs SSLParameters from the specified array of ciphersuites
     * and protocols.
     * <p>
     * Calling this constructor is equivalent to calling the no-args
     * constructor followed by
     * {@code setCipherSuites(cipherSuites); setProtocols(protocols);}.
     * Note that the standard list of cipher suite names may be found in the
     * <a href=
     * "{@docRoot}/../specs/security/standard-names.html#jsse-cipher-suite-names">
     * JSSE Cipher Suite Names</a> section of the Java Cryptography
     * Architecture Standard Algorithm Name Documentation.  Providers
     * may support cipher suite names not found in this list.
     *
     * @param cipherSuites the array of ciphersuites (or null)
     * @param protocols the array of protocols (or null)
     */
    public SSLParameters(String[] cipherSuites, String[] protocols) {
        super(cipherSuites, protocols);
    }
    /**
     * Sets whether DTLS handshake retransmissions should be enabled.
     *
     * This method only applies to DTLS.
     *
     * @param   enableRetransmissions
     *          {@code true} indicates that DTLS handshake retransmissions
     *          should be enabled; {@code false} indicates that DTLS handshake
     *          retransmissions should be disabled
     *
     * @see     #getEnableRetransmissions()
     *
     * @since 9
     */
    public void setEnableRetransmissions(boolean enableRetransmissions) {
        this.enableRetransmissions = enableRetransmissions;
    }

    /**
     * Returns whether DTLS handshake retransmissions should be enabled.
     *
     * This method only applies to DTLS.
     *
     * @return  true, if DTLS handshake retransmissions should be enabled
     *
     * @see     #setEnableRetransmissions(boolean)
     *
     * @since 9
     */
    public boolean getEnableRetransmissions() {
        return enableRetransmissions;
    }

    /**
     * Sets the maximum expected network packet size in bytes for
     * SSL/TLS/DTLS records.
     *
     * @apiNote  It is recommended that if possible, the maximum packet size
     *           should not be less than 256 bytes so that small handshake
     *           messages, such as HelloVerifyRequests, are not fragmented.
     *
     * @implNote If the maximum packet size is too small to hold a minimal
     *           record, an implementation may attempt to generate as minimal
     *           records as possible.  However, this may cause a generated
     *           packet to be larger than the maximum packet size.
     *
     * @param   maximumPacketSize
     *          the maximum expected network packet size in bytes, or
     *          {@code 0} to use the implicit size that is automatically
     *          specified by the underlying implementation.
     * @throws  IllegalArgumentException
     *          if {@code maximumPacketSize} is negative.
     *
     * @see     #getMaximumPacketSize()
     *
     * @since 9
     */
    public void setMaximumPacketSize(int maximumPacketSize) {
        if (maximumPacketSize < 0) {
            throw new IllegalArgumentException(
                "The maximum packet size cannot be negative");
        }

        this.maximumPacketSize = maximumPacketSize;
    }

    /**
     * Returns the maximum expected network packet size in bytes for
     * SSL/TLS/DTLS records.
     *
     * @apiNote  The implicit size may not be a fixed value, especially
     *           for a DTLS protocols implementation.
     *
     * @implNote For SSL/TLS/DTLS connections, the underlying provider
     *           should calculate and specify the implicit value of the
     *           maximum expected network packet size if it is not
     *           configured explicitly.  For any connection populated
     *           object, this method should never return {@code 0} so
     *           that applications can retrieve the actual implicit size
     *           of the underlying implementation.
     *           <P>
     *           An implementation should attempt to comply with the maximum
     *           packet size configuration.  However, if the maximum packet
     *           size is too small to hold a minimal record, an implementation
     *           may try to generate as minimal records as possible.  This
     *           may cause a generated packet to be larger than the maximum
     *           packet size.
     *
     * @return   the maximum expected network packet size, or {@code 0} if
     *           use the implicit size that is automatically specified by
     *           the underlying implementation and this object has not been
     *           populated by any connection.
     *
     * @see      #setMaximumPacketSize(int)
     *
     * @since 9
     */
    public int getMaximumPacketSize() {
        return maximumPacketSize;
    }
}
