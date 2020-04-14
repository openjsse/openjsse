/*
 * Copyright (c) 2003, 2018, Oracle and/or its affiliates. All rights reserved.
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

import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.util.List;
import java.util.function.BiFunction;

import javax.net.ssl.*;

/**
 * A class which enables secure communications using protocols such as
 * the Secure Sockets Layer (SSL) or
 * <A HREF="http://www.ietf.org/rfc/rfc2246.txt"> IETF RFC 2246 "Transport
 * Layer Security" (TLS) </A> protocols, but is transport independent.
 * <P>
 * The secure communications modes include: <UL>
 *
 *      <LI> <em>Integrity Protection</em>.  SSL/TLS/DTLS protects against
 *      modification of messages by an active wiretapper.
 *
 *      <LI> <em>Authentication</em>.  In most modes, SSL/TLS/DTLS provides
 *      peer authentication.  Servers are usually authenticated, and
 *      clients may be authenticated as requested by servers.
 *
 *      <LI> <em>Confidentiality (Privacy Protection)</em>.  In most
 *      modes, SSL/TLS/DTLS encrypts data being sent between client and
 *      server.  This protects the confidentiality of data, so that
 *      passive wiretappers won't see sensitive data such as financial
 *      information or personal information of many kinds.
 *
 *      </UL>
 *
 * These kinds of protection are specified by a "cipher suite", which
 * is a combination of cryptographic algorithms used by a given SSL
 * connection.  During the negotiation process, the two endpoints must
 * agree on a cipher suite that is available in both environments.  If
 * there is no such suite in common, no SSL connection can be
 * established, and no data can be exchanged.
 * <P>
 * The cipher suite used is established by a negotiation process called
 * "handshaking".  The goal of this process is to create or rejoin a
 * "session", which may protect many connections over time.  After
 * handshaking has completed, you can access session attributes by
 * using the {@link #getSession()} method.
 * <P>
 * The {@code SSLSocket} class provides much of the same security
 * functionality, but all of the inbound and outbound data is
 * automatically transported using the underlying {@link
 * java.net.Socket Socket}, which by design uses a blocking model.
 * While this is appropriate for many applications, this model does not
 * provide the scalability required by large servers.
 * <P>
 * The primary distinction of an {@code SSLEngine} is that it
 * operates on inbound and outbound byte streams, independent of the
 * transport mechanism.  It is the responsibility of the
 * {@code SSLEngine} user to arrange for reliable I/O transport to
 * the peer.  By separating the SSL/TLS/DTLS abstraction from the I/O
 * transport mechanism, the {@code SSLEngine} can be used for a
 * wide variety of I/O types, such as {@link
 * java.nio.channels.spi.AbstractSelectableChannel#configureBlocking(boolean)
 * non-blocking I/O (polling)}, {@link java.nio.channels.Selector
 * selectable non-blocking I/O}, {@link java.net.Socket Socket} and the
 * traditional Input/OutputStreams, local {@link java.nio.ByteBuffer
 * ByteBuffers} or byte arrays, <A
 * HREF="http://www.jcp.org/en/jsr/detail?id=203"> future asynchronous
 * I/O models </A>, and so on.
 * <P>
 * At a high level, the {@code SSLEngine} appears thus:
 *
 * <pre>
 *                   app data
 *
 *                |           ^
 *                |     |     |
 *                v     |     |
 *           +----+-----|-----+----+
 *           |          |          |
 *           |       SSL|Engine    |
 *   wrap()  |          |          |  unwrap()
 *           | OUTBOUND | INBOUND  |
 *           |          |          |
 *           +----+-----|-----+----+
 *                |     |     ^
 *                |     |     |
 *                v           |
 *
 *                   net data
 * </pre>
 * Application data (also known as plaintext or cleartext) is data which
 * is produced or consumed by an application.  Its counterpart is
 * network data, which consists of either handshaking and/or ciphertext
 * (encrypted) data, and destined to be transported via an I/O
 * mechanism.  Inbound data is data which has been received from the
 * peer, and outbound data is destined for the peer.
 * <P>
 * (In the context of an {@code SSLEngine}, the term "handshake
 * data" is taken to mean any data exchanged to establish and control a
 * secure connection.  Handshake data includes the SSL/TLS/DTLS messages
 * "alert", "change_cipher_spec," and "handshake.")
 * <P>
 * There are five distinct phases to an {@code SSLEngine}.
 *
 * <OL>
 *     <li> Creation - The {@code SSLEngine} has been created and
 *     initialized, but has not yet been used.  During this phase, an
 *     application may set any {@code SSLEngine}-specific settings
 *     (enabled cipher suites, whether the {@code SSLEngine} should
 *     handshake in client or server mode, and so on).  Once
 *     handshaking has begun, though, any new settings (except
 *     client/server mode, see below) will be used for
 *     the next handshake.
 *
 *     <li> Initial Handshake - The initial handshake is a procedure by
 *     which the two peers exchange communication parameters until an
 *     SSLSession is established.  Application data can not be sent during
 *     this phase.
 *
 *     <li> Application Data - Once the communication parameters have
 *     been established and the handshake is complete, application data
 *     may flow through the {@code SSLEngine}.  Outbound
 *     application messages are encrypted and integrity protected,
 *     and inbound messages reverse the process.
 *
 *     <li> Rehandshaking - Either side may request a renegotiation of
 *     the session at any time during the Application Data phase.  New
 *     handshaking data can be intermixed among the application data.
 *     Before starting the rehandshake phase, the application may
 *     reset the SSL/TLS/DTLS communication parameters such as the list of
 *     enabled ciphersuites and whether to use client authentication,
 *     but can not change between client/server modes.  As before, once
 *     handshaking has begun, any new {@code SSLEngine}
 *     configuration settings will not be used until the next
 *     handshake.
 *
 *     <li> Closure - When the connection is no longer needed, the client
 *     and the server applications should each close both sides of their
 *     respective connections.  For {@code SSLEngine} objects, an
 *     application should call {@link SSLEngine#closeOutbound()} and
 *     send any remaining messages to the peer.  Likewise, an application
 *     should receive any remaining messages from the peer before calling
 *     {@link SSLEngine#closeInbound()}.  The underlying transport mechanism
 *     can then be closed after both sides of the {@code SSLEngine} have
 *     been closed.  If the connection is not closed in an orderly manner
 *     (for example {@link SSLEngine#closeInbound()} is called before the
 *     peer's write closure notification has been received), exceptions
 *     will be raised to indicate that an error has occurred.  Once an
 *     engine is closed, it is not reusable: a new {@code SSLEngine}
 *     must be created.
 * </OL>
 * An {@code SSLEngine} is created by calling {@link
 * SSLContext#createSSLEngine()} from an initialized
 * {@code SSLContext}.  Any configuration
 * parameters should be set before making the first call to
 * {@code wrap()}, {@code unwrap()}, or
 * {@code beginHandshake()}.  These methods all trigger the
 * initial handshake.
 * <P>
 * Data moves through the engine by calling {@link #wrap(ByteBuffer,
 * ByteBuffer) wrap()} or {@link #unwrap(ByteBuffer, ByteBuffer)
 * unwrap()} on outbound or inbound data, respectively.  Depending on
 * the state of the {@code SSLEngine}, a {@code wrap()} call
 * may consume application data from the source buffer and may produce
 * network data in the destination buffer.  The outbound data
 * may contain application and/or handshake data.  A call to
 * {@code unwrap()} will examine the source buffer and may
 * advance the handshake if the data is handshaking information, or
 * may place application data in the destination buffer if the data
 * is application.  The state of the underlying SSL/TLS/DTLS algorithm
 * will determine when data is consumed and produced.
 * <P>
 * Calls to {@code wrap()} and {@code unwrap()} return an
 * {@code SSLEngineResult} which indicates the status of the
 * operation, and (optionally) how to interact with the engine to make
 * progress.
 * <P>
 * The {@code SSLEngine} produces/consumes complete SSL/TLS/DTLS
 * packets only, and does not store application data internally between
 * calls to {@code wrap()/unwrap()}.  Thus input and output
 * {@code ByteBuffer}s must be sized appropriately to hold the
 * maximum record that can be produced.  Calls to {@link
 * SSLSession#getPacketBufferSize()} and {@link
 * SSLSession#getApplicationBufferSize()} should be used to determine
 * the appropriate buffer sizes.  The size of the outbound application
 * data buffer generally does not matter.  If buffer conditions do not
 * allow for the proper consumption/production of data, the application
 * must determine (via {@link SSLEngineResult}) and correct the
 * problem, and then try the call again.
 * <P>
 * For example, {@code unwrap()} will return a {@link
 * SSLEngineResult.Status#BUFFER_OVERFLOW} result if the engine
 * determines that there is not enough destination buffer space available.
 * Applications should call {@link SSLSession#getApplicationBufferSize()}
 * and compare that value with the space available in the destination buffer,
 * enlarging the buffer if necessary.  Similarly, if {@code unwrap()}
 * were to return a {@link SSLEngineResult.Status#BUFFER_UNDERFLOW}, the
 * application should call {@link SSLSession#getPacketBufferSize()} to ensure
 * that the source buffer has enough room to hold a record (enlarging if
 * necessary), and then obtain more inbound data.
 *
 * <pre>{@code
 *   SSLEngineResult r = engine.unwrap(src, dst);
 *   switch (r.getStatus()) {
 *   BUFFER_OVERFLOW:
 *       // Could attempt to drain the dst buffer of any already obtained
 *       // data, but we'll just increase it to the size needed.
 *       int appSize = engine.getSession().getApplicationBufferSize();
 *       ByteBuffer b = ByteBuffer.allocate(appSize + dst.position());
 *       dst.flip();
 *       b.put(dst);
 *       dst = b;
 *       // retry the operation.
 *       break;
 *   BUFFER_UNDERFLOW:
 *       int netSize = engine.getSession().getPacketBufferSize();
 *       // Resize buffer if needed.
 *       if (netSize > dst.capacity()) {
 *           ByteBuffer b = ByteBuffer.allocate(netSize);
 *           src.flip();
 *           b.put(src);
 *           src = b;
 *       }
 *       // Obtain more inbound network data for src,
 *       // then retry the operation.
 *       break;
 *   // other cases: CLOSED, OK.
 *   }
 * }</pre>
 *
 * <P>
 * Unlike {@code SSLSocket}, all methods of SSLEngine are
 * non-blocking.  {@code SSLEngine} implementations may
 * require the results of tasks that may take an extended period of
 * time to complete, or may even block.  For example, a TrustManager
 * may need to connect to a remote certificate validation service,
 * or a KeyManager might need to prompt a user to determine which
 * certificate to use as part of client authentication.  Additionally,
 * creating cryptographic signatures and verifying them can be slow,
 * seemingly blocking.
 * <P>
 * For any operation which may potentially block, the
 * {@code SSLEngine} will create a {@link java.lang.Runnable}
 * delegated task.  When {@code SSLEngineResult} indicates that a
 * delegated task result is needed, the application must call {@link
 * #getDelegatedTask()} to obtain an outstanding delegated task and
 * call its {@link java.lang.Runnable#run() run()} method (possibly using
 * a different thread depending on the compute strategy).  The
 * application should continue obtaining delegated tasks until no more
 * exist, and try the original operation again.
 * <P>
 * At the end of a communication session, applications should properly
 * close the SSL/TLS/DTLS link.  The SSL/TLS/DTLS protocols have closure
 * handshake messages, and these messages should be communicated to the
 * peer before releasing the {@code SSLEngine} and closing the
 * underlying transport mechanism.  A close can be initiated by one of:
 * an SSLException, an inbound closure handshake message, or one of the
 * close methods.  In all cases, closure handshake messages are
 * generated by the engine, and {@code wrap()} should be repeatedly
 * called until the resulting {@code SSLEngineResult}'s status
 * returns "CLOSED", or {@link #isOutboundDone()} returns true.  All
 * data obtained from the {@code wrap()} method should be sent to the
 * peer.
 * <P>
 * {@link #closeOutbound()} is used to signal the engine that the
 * application will not be sending any more data.
 * <P>
 * A peer will signal its intent to close by sending its own closure
 * handshake message.  After this message has been received and
 * processed by the local {@code SSLEngine}'s {@code unwrap()}
 * call, the application can detect the close by calling
 * {@code unwrap()} and looking for a {@code SSLEngineResult}
 * with status "CLOSED", or if {@link #isInboundDone()} returns true.
 * If for some reason the peer closes the communication link without
 * sending the proper SSL/TLS/DTLS closure message, the application can
 * detect the end-of-stream and can signal the engine via {@link
 * #closeInbound()} that there will no more inbound messages to
 * process.  Some applications might choose to require orderly shutdown
 * messages from a peer, in which case they can check that the closure
 * was generated by a handshake message and not by an end-of-stream
 * condition.
 * <P>
 * There are two groups of cipher suites which you will need to know
 * about when managing cipher suites:
 *
 * <UL>
 *      <LI> <em>Supported</em> cipher suites:  all the suites which are
 *      supported by the SSL implementation.  This list is reported
 *      using {@link #getSupportedCipherSuites()}.
 *
 *      <LI> <em>Enabled</em> cipher suites, which may be fewer than
 *      the full set of supported suites.  This group is set using the
 *      {@link #setEnabledCipherSuites(String [])} method, and
 *      queried using the {@link #getEnabledCipherSuites()} method.
 *      Initially, a default set of cipher suites will be enabled on a
 *      new engine that represents the minimum suggested
 *      configuration.
 * </UL>
 *
 * Implementation defaults require that only cipher suites which
 * authenticate servers and provide confidentiality be enabled by
 * default.  Only if both sides explicitly agree to unauthenticated
 * and/or non-private (unencrypted) communications will such a
 * cipher suite be selected.
 * <P>
 * Each SSL/TLS/DTLS connection must have one client and one server, thus
 * each endpoint must decide which role to assume.  This choice determines
 * who begins the handshaking process as well as which type of messages
 * should be sent by each party.  The method {@link
 * #setUseClientMode(boolean)} configures the mode.  Once the initial
 * handshaking has started, an {@code SSLEngine} can not switch
 * between client and server modes, even when performing renegotiations.
 * <P>
 * Applications might choose to process delegated tasks in different
 * threads.  When an {@code SSLEngine}
 * is created, the current {@link java.security.AccessControlContext}
 * is saved.  All future delegated tasks will be processed using this
 * context:  that is, all access control decisions will be made using the
 * context captured at engine creation.
 *
 * <HR>
 *
 * <B>Concurrency Notes</B>:
 * There are two concurrency issues to be aware of:
 *
 * <OL>
 *      <li>The {@code wrap()} and {@code unwrap()} methods
 *      may execute concurrently of each other.
 *
 *      <li> The SSL/TLS/DTLS protocols employ ordered packets.
 *      Applications must take care to ensure that generated packets
 *      are delivered in sequence.  If packets arrive
 *      out-of-order, unexpected or fatal results may occur.
 * <P>
 *      For example:
 *
 *      <pre>
 *              synchronized (outboundLock) {
 *                  sslEngine.wrap(src, dst);
 *                  outboundQueue.put(dst);
 *              }
 *      </pre>
 *
 *      As a corollary, two threads must not attempt to call the same method
 *      (either {@code wrap()} or {@code unwrap()}) concurrently,
 *      because there is no way to guarantee the eventual packet ordering.
 * </OL>
 *
 * @see SSLContext
 * @see SSLSocket
 * @see SSLServerSocket
 * @see SSLSession
 * @see java.net.Socket
 *
 * @author Brad R. Wetmore
 */

public abstract class SSLEngine extends javax.net.ssl.SSLEngine {

    /**
     * Constructor for an <code>SSLEngine</code> providing no hints
     * for an internal session reuse strategy.
     *
     * @see     SSLContext#createSSLEngine()
     * @see     SSLSessionContext
     */
    protected SSLEngine() {
        super();
    }

    /**
     * Constructor for an <code>SSLEngine</code>.
     * <P>
     * <code>SSLEngine</code> implementations may use the
     * <code>peerHost</code> and <code>peerPort</code> parameters as hints
     * for their internal session reuse strategy.
     * <P>
     * Some cipher suites (such as Kerberos) require remote hostname
     * information. Implementations of this class should use this
     * constructor to use Kerberos.
     * <P>
     * The parameters are not authenticated by the
     * <code>SSLEngine</code>.
     *
     * @param   peerHost the name of the peer host
     * @param   peerPort the port number of the peer
     * @see     SSLContext#createSSLEngine(String, int)
     * @see     SSLSessionContext
     */
    protected SSLEngine(String peerHost, int peerPort) {
        super(peerHost, peerPort);
    }

    /**
     * Returns <code>True</code> if the {@code SSLEngine} needs to unwrap 
     * before handshaking can continue.
     *
     * @return  <code>True</code> if unwrap again is required.
     */
    public abstract boolean needUnwrapAgain();

}
