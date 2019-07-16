/*
 * Copyright (c) 1997, 2018, Oracle and/or its affiliates. All rights reserved.
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

import java.io.IOException;
import java.net.*;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.*;

/**
 * This class extends <code>Socket</code> and provides secure
 * sockets using protocols such as the "Secure
 * Sockets Layer" (SSL) or IETF "Transport Layer Security" (TLS) protocols.
 * <P>
 * Such sockets are normal stream sockets, but they
 * add a layer of security protections over the underlying network transport
 * protocol, such as TCP.  Those protections include: <UL>
 *
 *      <LI> <em>Integrity Protection</em>.  SSL protects against
 *      modification of messages by an active wiretapper.
 *
 *      <LI> <em>Authentication</em>.  In most modes, SSL provides
 *      peer authentication.  Servers are usually authenticated,
 *      and clients may be authenticated as requested by servers.
 *
 *      <LI> <em>Confidentiality (Privacy Protection)</em>.  In most
 *      modes, SSL encrypts data being sent between client and server.
 *      This protects the confidentiality of data, so that passive
 *      wiretappers won't see sensitive data such as financial
 *      information or personal information of many kinds.
 *
 *      </UL>
 *
 * <P>These kinds of protection are specified by a "cipher suite", which
 * is a combination of cryptographic algorithms used by a given SSL connection.
 * During the negotiation process, the two endpoints must agree on
 * a ciphersuite that is available in both environments.
 * If there is no such suite in common, no SSL connection can
 * be established, and no data can be exchanged.
 *
 * <P> The cipher suite used is established by a negotiation process
 * called "handshaking".  The goal of this
 * process is to create or rejoin a "session", which may protect many
 * connections over time.  After handshaking has completed, you can access
 * session attributes by using the <em>getSession</em> method.
 * The initial handshake on this connection can be initiated in
 * one of three ways: <UL>
 *
 *      <LI> calling <code>startHandshake</code> which explicitly
 *              begins handshakes, or
 *      <LI> any attempt to read or write application data on
 *              this socket causes an implicit handshake, or
 *      <LI> a call to <code>getSession</code> tries to set up a session
 *              if there is no currently valid session, and
 *              an implicit handshake is done.
 * </UL>
 *
 * <P>If handshaking fails for any reason, the <code>SSLSocket</code>
 * is closed, and no further communications can be done.
 *
 * <P>There are two groups of cipher suites which you will need to know
 * about when managing cipher suites: <UL>
 *
 *      <LI> <em>Supported</em> cipher suites:  all the suites which are
 *      supported by the SSL implementation.  This list is reported
 *      using <em>getSupportedCipherSuites</em>.
 *
 *      <LI> <em>Enabled</em> cipher suites, which may be fewer
 *      than the full set of supported suites.  This group is
 *      set using the <em>setEnabledCipherSuites</em> method, and
 *      queried using the <em>getEnabledCipherSuites</em> method.
 *      Initially, a default set of cipher suites will be enabled on
 *      a new socket that represents the minimum suggested configuration.
 *
 *      </UL>
 *
 * <P> Implementation defaults require that only cipher
 * suites which authenticate servers and provide confidentiality
 * be enabled by default.
 * Only if both sides explicitly agree to unauthenticated and/or
 * non-private (unencrypted) communications will such a ciphersuite be
 * selected.
 *
 * <P>When an <code>SSLSocket</code> is first created, no handshaking
 * is done so that applications may first set their communication
 * preferences:  what cipher suites to use, whether the socket should be
 * in client or server mode, etc.
 * However, security is always provided by the time that application data
 * is sent over the connection.
 *
 * <P> You may register to receive event notification of handshake
 * completion.  This involves
 * the use of two additional classes.  <em>HandshakeCompletedEvent</em>
 * objects are passed to <em>HandshakeCompletedListener</em> instances,
 * which are registered by users of this API.
 *
 * An <code>SSLSocket</code> is created by <code>SSLSocketFactory</code>,
 * or by <code>accept</code>ing a connection from a
 * <code>SSLServerSocket</code>.
 *
 * <P>A SSL socket must choose to operate in the client or server mode.
 * This will determine who begins the handshaking process, as well
 * as which messages should be sent by each party.  Each
 * connection must have one client and one server, or handshaking
 * will not progress properly.  Once the initial handshaking has started, a
 * socket can not switch between client and server modes, even when
 * performing renegotiations.
 *
 * @apiNote
 * When the connection is no longer needed, the client and server
 * applications should each close both sides of their respective connection.
 * For {@code SSLSocket} objects, for example, an application can call
 * {@link Socket#shutdownOutput()} or {@link java.io.OutputStream#close()}
 * for output strean close and call {@link Socket#shutdownInput()} or
 * {@link java.io.InputStream#close()} for input stream close.  Note that
 * in some cases, closing the input stream may depend on the peer's output
 * stream being closed first.  If the connection is not closed in an orderly
 * manner (for example {@link Socket#shutdownInput()} is called before the
 * peer's write closure notification has been received), exceptions may
 * be raised to indicate that an error has occurred.  Once an
 * {@code SSLSocket} is closed, it is not reusable: a new {@code SSLSocket}
 * must be created.
 *
 * @see java.net.Socket
 * @see SSLServerSocket
 * @see SSLSocketFactory
 *
 * @author David Brownell
 */
public abstract class SSLSocket extends javax.net.ssl.SSLSocket
{
    /**
     * Returns the most recent application protocol value negotiated for this
     * connection.
     * <p>
     * If supported by the underlying SSL/TLS/DTLS implementation,
     * application name negotiation mechanisms such as <a
     * href="http://www.ietf.org/rfc/rfc7301.txt"> RFC 7301 </a>, the
     * Application-Layer Protocol Negotiation (ALPN), can negotiate
     * application-level values between peers.
     *
     * @implSpec
     * The implementation in this class throws
     * {@code UnsupportedOperationException} and performs no other action.
     *
     * @return null if it has not yet been determined if application
     *         protocols might be used for this connection, an empty
     *         {@code String} if application protocols values will not
     *         be used, or a non-empty application protocol {@code String}
     *         if a value was successfully negotiated.
     * @throws UnsupportedOperationException if the underlying provider
     *         does not implement the operation.
     * @since 9
     */
    public String getApplicationProtocol() {
        throw new UnsupportedOperationException();
    }

    /**
     * Returns the application protocol value negotiated on a SSL/TLS
     * handshake currently in progress.
     * <p>
     * Like {@link #getHandshakeSession()},
     * a connection may be in the middle of a handshake. The
     * application protocol may or may not yet be available.
     *
     * @implSpec
     * The implementation in this class throws
     * {@code UnsupportedOperationException} and performs no other action.
     *
     * @return null if it has not yet been determined if application
     *         protocols might be used for this handshake, an empty
     *         {@code String} if application protocols values will not
     *         be used, or a non-empty application protocol {@code String}
     *         if a value was successfully negotiated.
     * @throws UnsupportedOperationException if the underlying provider
     *         does not implement the operation.
     * @since 9
     */
    public String getHandshakeApplicationProtocol() {
        throw new UnsupportedOperationException();
    }


    /**
     * Registers a callback function that selects an application protocol
     * value for a SSL/TLS/DTLS handshake.
     * The function overrides any values supplied using
     * {@link SSLParameters#setApplicationProtocols
     * SSLParameters.setApplicationProtocols} and it supports the following
     * type parameters:
     * <blockquote>
     * <dl>
     * <dt> {@code SSLSocket}
     * <dd> The function's first argument allows the current {@code SSLSocket}
     *      to be inspected, including the handshake session and configuration
     *      settings.
     * <dt> {@code List<String>}
     * <dd> The function's second argument lists the application protocol names
     *      advertised by the TLS peer.
     * <dt> {@code String}
     * <dd> The function's result is an application protocol name, or null to
     *      indicate that none of the advertised names are acceptable.
     *      If the return value is an empty {@code String} then application
     *      protocol indications will not be used.
     *      If the return value is null (no value chosen) or is a value that
     *      was not advertised by the peer, the underlying protocol will
     *      determine what action to take. (For example, ALPN will send a
     *      "no_application_protocol" alert and terminate the connection.)
     * </dl>
     * </blockquote>
     *
     * For example, the following call registers a callback function that
     * examines the TLS handshake parameters and selects an application protocol
     * name:
     * <pre>{@code
     *     serverSocket.setHandshakeApplicationProtocolSelector(
     *         (serverSocket, clientProtocols) -> {
     *             SSLSession session = serverSocket.getHandshakeSession();
     *             return chooseApplicationProtocol(
     *                 serverSocket,
     *                 clientProtocols,
     *                 session.getProtocol(),
     *                 session.getCipherSuite());
     *         });
     * }</pre>
     *
     * @apiNote
     * This method should be called by TLS server applications before the TLS
     * handshake begins. Also, this {@code SSLSocket} should be configured with
     * parameters that are compatible with the application protocol selected by
     * the callback function. For example, enabling a poor choice of cipher
     * suites could result in no suitable application protocol.
     * See {@link SSLParameters}.
     *
     * @implSpec
     * The implementation in this class throws
     * {@code UnsupportedOperationException} and performs no other action.
     *
     * @param selector the callback function, or null to de-register.
     * @throws UnsupportedOperationException if the underlying provider
     *         does not implement the operation.
     * @since 9
     */
    public void setHandshakeApplicationProtocolSelector(
            BiFunction<SSLSocket, List<String>, String> selector) {
        throw new UnsupportedOperationException();
    }

    /**
     * Retrieves the callback function that selects an application protocol
     * value during a SSL/TLS/DTLS handshake.
     * See {@link #setHandshakeApplicationProtocolSelector
     * setHandshakeApplicationProtocolSelector}
     * for the function's type parameters.
     *
     * @implSpec
     * The implementation in this class throws
     * {@code UnsupportedOperationException} and performs no other action.
     *
     * @return the callback function, or null if none has been set.
     * @throws UnsupportedOperationException if the underlying provider
     *         does not implement the operation.
     * @since 9
     */
    public BiFunction<SSLSocket, List<String>, String>
            getHandshakeApplicationProtocolSelector() {
        throw new UnsupportedOperationException();
    }
}
