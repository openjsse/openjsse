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

    /**
     * Returns a prioritized array of application-layer protocol names that
     * can be negotiated over the SSL/TLS/DTLS protocols.
     * <p>
     * The array could be empty (zero-length), in which case protocol
     * indications will not be used.
     * <p>
     * This method will return a new array each time it is invoked.
     *
     * @return a non-null, possibly zero-length array of application protocol
     *         {@code String}s.  The array is ordered based on protocol
     *         preference, with {@code protocols[0]} being the most preferred.
     * @see #setApplicationProtocols
     * @since 9
     */
    public String[] getApplicationProtocols() {
        return applicationProtocols.clone();
    }

    /**
     * Sets the prioritized array of application-layer protocol names that
     * can be negotiated over the SSL/TLS/DTLS protocols.
     * <p>
     * If application-layer protocols are supported by the underlying
     * SSL/TLS implementation, this method configures which values can
     * be negotiated by protocols such as <a
     * href="http://www.ietf.org/rfc/rfc7301.txt"> RFC 7301 </a>, the
     * Application Layer Protocol Negotiation (ALPN).
     * <p>
     * If this end of the connection is expected to offer application protocol
     * values, all protocols configured by this method will be sent to the
     * peer.
     * <p>
     * If this end of the connection is expected to select the application
     * protocol value, the {@code protocols} configured by this method are
     * compared with those sent by the peer.  The first matched value becomes
     * the negotiated value.  If none of the {@code protocols} were actually
     * requested by the peer, the underlying protocol will determine what
     * action to take.  (For example, ALPN will send a
     * {@code "no_application_protocol"} alert and terminate the connection.)
     *
     * @implSpec
     * This method will make a copy of the {@code protocols} array.
     *
     * @param protocols   an ordered array of application protocols,
     *                    with {@code protocols[0]} being the most preferred.
     *                    If the array is empty (zero-length), protocol
     *                    indications will not be used.
     * @throws IllegalArgumentException if protocols is null, or if
     *                    any element in a non-empty array is null or an
     *                    empty (zero-length) string
     * @see #getApplicationProtocols
     * @since 9
     */
    public void setApplicationProtocols(String[] protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("protocols was null");
        }

        String[] tempProtocols = protocols.clone();

        for (String p : tempProtocols) {
            if (p == null || p.equals("")) {
                throw new IllegalArgumentException(
                    "An element of protocols was null/empty");
            }
        }
        applicationProtocols = tempProtocols;
    }
}
