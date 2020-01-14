/*
 * Copyright (c) 2003, 2017, Oracle and/or its affiliates. All rights reserved.
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
import javax.net.ssl.*;

/**
 * An encapsulation of the result state produced by
 * {@code SSLEngine} I/O calls.
 *
 * <p> A {@code SSLEngine} provides a means for establishing
 * secure communication sessions between two peers.  {@code SSLEngine}
 * operations typically consume bytes from an input buffer and produce
 * bytes in an output buffer.  This class provides operational result
 * values describing the state of the {@code SSLEngine}, including
 * indications of what operations are needed to finish an
 * ongoing handshake.  Lastly, it reports the number of bytes consumed
 * and produced as a result of this operation.
 *
 * @see SSLEngine
 * @see SSLEngine#wrap(ByteBuffer, ByteBuffer)
 * @see SSLEngine#unwrap(ByteBuffer, ByteBuffer)
 *
 * @author Brad R. Wetmore
 */

public class SSLEngineResult extends javax.net.ssl.SSLEngineResult {

    private final boolean needUnwrapAgain;

    /**
     * Initializes a new instance of this class.
     *
     * @param   status
     *          the return value of the operation.
     *
     * @param   handshakeStatus
     *          the current handshaking status.
     *
     * @param   bytesConsumed
     *          the number of bytes consumed from the source ByteBuffer
     *
     * @param   bytesProduced
     *          the number of bytes placed into the destination ByteBuffer
     *
     * @throws  IllegalArgumentException
     *          if the {@code status} or {@code handshakeStatus}
     *          arguments are null, or if {@code bytesConsumed} or
     *          {@code bytesProduced} is negative.
     */
    public SSLEngineResult(Status status, HandshakeStatus handshakeStatus,
            int bytesConsumed, int bytesProduced) {
        this(status, handshakeStatus, bytesConsumed, bytesProduced, -1, false);
    }

    /**
     * Initializes a new instance of this class.
     *
     * @param   status
     *          the return value of the operation.
     *
     * @param   handshakeStatus
     *          the current handshaking status.
     *
     * @param   bytesConsumed
     *          the number of bytes consumed from the source ByteBuffer
     *
     * @param   bytesProduced
     *          the number of bytes placed into the destination ByteBuffer
     *
     * @param   sequenceNumber
     *          the sequence number (unsigned long) of the produced or
     *          consumed SSL/TLS/DTLS record, or {@code -1L} if no record
     *          produced or consumed
     *
     * @param   needUnwrapAgain
     *          The {@code SSLEngine} needs to unwrap before handshaking can
     *          continue.
     * 
     * @throws  IllegalArgumentException
     *          if the {@code status} or {@code handshakeStatus}
     *          arguments are null, or if {@code bytesConsumed} or
     *          {@code bytesProduced} is negative
     *
     * @since   9
     */
    public SSLEngineResult(Status status, HandshakeStatus handshakeStatus,
            int bytesConsumed, int bytesProduced, long sequenceNumber,
            boolean needUnwrapAgain) {
        super(status, handshakeStatus, bytesConsumed,
                bytesProduced, sequenceNumber);
        this.needUnwrapAgain = needUnwrapAgain;
    }

    /**
     * Returns <code>True</code> if the {@code SSLEngine} needs to unwrap 
     * before handshaking can continue.
     *
     * @return  <code>True</code> if unwrap again is required.
     */
    public final boolean needUnwrapAgain() {
        return needUnwrapAgain;
    }
}
