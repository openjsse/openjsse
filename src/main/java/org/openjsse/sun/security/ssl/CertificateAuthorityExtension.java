/*
 * Copyright 2020 Azul Systems, Inc.
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

import org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer;
import org.openjsse.sun.security.ssl.SSLExtension.SSLExtensionSpec;
import org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

import javax.net.ssl.SSLProtocolException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.*;

import java.security.cert.Certificate;
import javax.security.auth.x500.X500Principal;

/**
 * Pack of the "certificate_authorities" extensions [RFC 8446].
 */
final class CertificateAuthorityExtension {
    static final HandshakeProducer chNetworkProducer =
            new CHCertificateAuthoritiesProducer();
    static final ExtensionConsumer chOnLoadConsumer =
            new CHCertificateAuthoritiesConsumer();
    static final HandshakeConsumer chOnTradeConsumer =
            new CHCertificateAuthoritiesUpdate();

    static final HandshakeProducer crNetworkProducer =
            new CRCertificateAuthoritiesProducer();
    static final ExtensionConsumer crOnLoadConsumer =
            new CRCertificateAuthoritiesConsumer();
    static final HandshakeConsumer crOnTradeConsumer =
            new CRCertificateAuthoritiesUpdate();

    static final SSLStringizer ssStringizer =
            new CertificateAuthoritiesStringizer();

    /**
     * The "certificate_authorities" extension.
     */
    static final class CertificateAuthoritiesSpec implements SSLExtensionSpec {
        final X500Principal[] authorities;

        CertificateAuthoritiesSpec(List<X500Principal> authorities) {
            if (authorities != null) {
                this.authorities = new X500Principal[authorities.size()];
                int i = 0;
                for (X500Principal name : authorities) {
                    this.authorities[i++] = name;
                }
            } else {
                this.authorities = new X500Principal[0];
            }
        }

        CertificateAuthoritiesSpec(ByteBuffer buffer) throws IOException {
            if (buffer.remaining() < 2) {      // 2: the length of the list
                throw new SSLProtocolException(
                    "Invalid signature_algorithms: insufficient data");
            }
            // read number of certificate authorities
            int caLength = Record.getInt16(buffer);
            if (buffer.remaining() != caLength) {
                throw new SSLProtocolException(
                        "Invalid certificate_authorities: incorrect data size");
            }
            ArrayList<X500Principal> dnList = new ArrayList<X500Principal>();
            while(buffer.remaining()>0) {
                byte dn[] = Record.getBytes16(buffer);
                X500Principal ca = new X500Principal(dn);
                dnList.add(ca);
            }
            this.authorities = dnList.toArray(new X500Principal[dnList.size()]);
        }

        X500Principal[] getAuthorities() {
            return authorities;
        }

        @Override
        public String toString() {
            MessageFormat messageFormat = new MessageFormat(
                "\"certificate authorities\": '['{0}']'", Locale.ENGLISH);

            if (authorities == null || authorities.length == 0) {
                Object[] messageFields = {
                        "<no supported certificate authorities specified>"
                    };
                return messageFormat.format(messageFields);
            } else {
                StringBuilder builder = new StringBuilder(512);
                boolean isFirst = true;
                for (X500Principal ca : authorities) {
                    if (isFirst) {
                        isFirst = false;
                    } else {
                        builder.append("]; [");
                    }

                    builder.append(ca);
                }

                Object[] messageFields = {
                        builder.toString()
                    };

                return messageFormat.format(messageFields);
            }
        }
    }

    private static final
            class CertificateAuthoritiesStringizer implements SSLStringizer {
        @Override
        public String toString(ByteBuffer buffer) {
            try {
                return (new CertificateAuthoritiesSpec(buffer)).toString();
            } catch (IOException ioe) {
                // For debug logging only, so please swallow exceptions.
                return ioe.getMessage();
            }
        }
    }

    /**
     * Network data producer of a "certificate_authority" extension in
     * the ClientHello handshake message.
     */
    private static final
            class CHCertificateAuthoritiesProducer implements HandshakeProducer {

        private final boolean enableCAExtension = Utilities.getBooleanProperty(
                "org.openjsse.client.enableCAExtension", false);

        private final int maxCAExtensionSize = Utilities.getUIntProperty(
                "org.openjsse.client.maxCAExtensionSize", 8192);

        // Prevent instantiation of this class.
        private CHCertificateAuthoritiesProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            // Is it a supported and enabled extension?
            if (!chc.sslConfig.isAvailable(
                    SSLExtension.CH_CERTIFICATE_AUTHORITIES)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                        "Ignore unavailable certificate_authorities extension");
                }
                return null;
            }
            if (!enableCAExtension) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Ignore disabled certificate_authorities extension");
                }
                return null;
            }

            // Produce the extension.
            if (chc.localSupportedAuthorities == null) {
                // Initialization of localSupportedAuthorities
                X509Certificate[] caCerts = chc.sslContext.getX509TrustManager().getAcceptedIssuers();
                ArrayList<X500Principal> authList = new ArrayList<X500Principal>(caCerts.length);
                for (X509Certificate cert: caCerts) {
                    authList.add(cert.getSubjectX500Principal());
                }
                if (!authList.isEmpty())
                    chc.localSupportedAuthorities = authList;
            }

            if (chc.localSupportedAuthorities == null)
                return null;
            int vectorLen = 0;
            List<byte[]> authorities = new ArrayList<byte[]>();
            for(X500Principal ca: chc.localSupportedAuthorities) {
                byte enc[] = ca.getEncoded();
                int len = enc.length + 2;
                if ((vectorLen + len) <=  maxCAExtensionSize) {
                    vectorLen += len;
                    authorities.add(enc);
                }
            }

            byte[] extData = new byte[vectorLen+2];
            ByteBuffer m = ByteBuffer.wrap(extData);
            Record.putInt16(m, vectorLen);
            for (byte[] enc : authorities) {
                Record.putBytes16(m,enc);
            }
            // Update the context.
            chc.handshakeExtensions.put(
                    SSLExtension.CH_CERTIFICATE_AUTHORITIES,
                    new CertificateAuthoritiesSpec(chc.localSupportedAuthorities));

            return extData;
       }
    }

    /**
     * Network data consumer of a "certificate_authority" extension in
     * the ClientHello handshake message.
     */
    private static final
            class CHCertificateAuthoritiesConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private CHCertificateAuthoritiesConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
            HandshakeMessage message, ByteBuffer buffer) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // Is it a supported and enabled extension?
            if (!shc.sslConfig.isAvailable(
                    SSLExtension.CH_CERTIFICATE_AUTHORITIES)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                        "Ignore unavailable certificate_authorities extension");
                }
                return;     // ignore the extension
            }

            // Parse the extension.
            CertificateAuthoritiesSpec spec;
            try {
                spec = new CertificateAuthoritiesSpec(buffer);
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }

            // Update the context.
            shc.handshakeExtensions.put(
                    SSLExtension.CH_CERTIFICATE_AUTHORITIES, spec);

            // No impact on session resumption.
        }
    }

    /**
     * After session creation consuming of a "certificate_authority"
     * extension in the ClientHello handshake message.
     */
    private static final class CHCertificateAuthoritiesUpdate
            implements HandshakeConsumer {
        // Prevent instantiation of this class.
        private CHCertificateAuthoritiesUpdate() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            CertificateAuthoritiesSpec spec =
                    (CertificateAuthoritiesSpec)shc.handshakeExtensions.get(
                            SSLExtension.CH_CERTIFICATE_AUTHORITIES);
            if (spec == null) {
                // Ignore, no "certificate_authority" extension requested.
                return;
            }

            // update the context
            shc.peerSupportedAuthorities = spec.getAuthorities();
        }
    }

    /**
     * Network data producer of a "certificate_authority" extension in
     * the CertificateRequest handshake message.
     */
    private static final
            class CRCertificateAuthoritiesProducer implements HandshakeProducer {

        private final boolean enableCAExtension = Utilities.getBooleanProperty(
                "org.openjsse.server.enableCAExtension", true);

        private final int maxCAExtensionSize = Utilities.getUIntProperty(
                "org.openjsse.server.maxCAExtensionSize", 8192);

        // Prevent instantiation of this class.
        private CRCertificateAuthoritiesProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // Is it a supported and enabled extension?
            if (!shc.sslConfig.isAvailable(
                    SSLExtension.CR_CERTIFICATE_AUTHORITIES)) {
                throw shc.conContext.fatal(Alert.MISSING_EXTENSION,
                        "No available certificate_authority extension " +
                        "for client certificate authentication");
            }

            if (!enableCAExtension) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Ignore disabled certificate_authorities extension");
                }
                return null;
            }

            // Produce the extension.
            if (shc.localSupportedAuthorities == null) {
                X509Certificate[] caCerts = shc.sslContext.getX509TrustManager().getAcceptedIssuers();
                ArrayList<X500Principal> authList = new ArrayList<X500Principal>(caCerts.length);
                for (X509Certificate cert: caCerts) {
                    authList.add(cert.getSubjectX500Principal());
                }
                if (!authList.isEmpty())
                    shc.localSupportedAuthorities = authList;
            }

            if (shc.localSupportedAuthorities == null)
                return null;

            int vectorLen = 0;
            List<byte[]> authorities = new ArrayList<byte[]>();
            for(X500Principal ca: shc.localSupportedAuthorities) {
                byte enc[] = ca.getEncoded();
                int len = enc.length + 2;
                if ((vectorLen + len) <=  maxCAExtensionSize) {
                    vectorLen += len;
                    authorities.add(enc);
                }
            }

            byte[] extData = new byte[vectorLen+2];
            ByteBuffer m = ByteBuffer.wrap(extData);
            Record.putInt16(m, vectorLen);
            for (byte[] enc : authorities) {
                Record.putBytes16(m,enc);
            }
            // Update the context.
            shc.handshakeExtensions.put(
                    SSLExtension.CR_CERTIFICATE_AUTHORITIES,
                    new CertificateAuthoritiesSpec(shc.localSupportedAuthorities));

            return extData;
        }
    }

    /**
     * Network data consumer of a "certificate_authority" extension in
     * the CertificateRequest handshake message.
     */
    private static final
            class CRCertificateAuthoritiesConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private CRCertificateAuthoritiesConsumer() {
            // blank
        }
        @Override
        public void consume(ConnectionContext context,
            HandshakeMessage message, ByteBuffer buffer) throws IOException {
            // The consuming happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            // Is it a supported and enabled extension?
            if (!chc.sslConfig.isAvailable(
                    SSLExtension.CR_CERTIFICATE_AUTHORITIES)) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "No available certificate_authority extension " +
                        "for client certificate authentication");
            }

            // Parse the extension.
            CertificateAuthoritiesSpec spec;
            try {
                spec = new CertificateAuthoritiesSpec(buffer);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }


            // Update the context.
            chc.handshakeExtensions.put(
                    SSLExtension.CR_CERTIFICATE_AUTHORITIES, spec);

            // No impact on session resumption.
        }
    }

    /**
     * After session creation consuming of a "certificate_authority"
     * extension in the CertificateRequest handshake message.
     */
    private static final class CRCertificateAuthoritiesUpdate
            implements HandshakeConsumer {
        // Prevent instantiation of this class.
        private CRCertificateAuthoritiesUpdate() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The consuming happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            CertificateAuthoritiesSpec spec =
                    (CertificateAuthoritiesSpec)chc.handshakeExtensions.get(
                            SSLExtension.CR_CERTIFICATE_AUTHORITIES);
            if (spec == null) {
                // Ignore, no "certificate_authority" extension requested.
                return;
            }

            // update the context
            chc.peerSupportedAuthorities = spec.getAuthorities();
        }
    }
}
