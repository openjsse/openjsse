/*
 * Copyright (c) 1996, 2013, Oracle and/or its affiliates. All rights reserved.
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

package org.openjsse.sun.security.x509;

import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import java.security.InvalidAlgorithmParameterException;
import java.security.ProviderException;
import java.security.cert.CertificateException;
import org.openjsse.sun.security.util.SignatureUtil;

import sun.security.x509.*;
import java.lang.reflect.Field;

/**
 * The X509CertImpl class represents an X.509 certificate. These certificates
 * are widely used to support authentication and other functionality in
 * Internet security systems.  Common applications include Privacy Enhanced
 * Mail (PEM), Transport Layer Security (SSL), code signing for trusted
 * software distribution, and Secure Electronic Transactions (SET).  There
 * is a commercial infrastructure ready to manage large scale deployments
 * of X.509 identity certificates.
 *
 * <P>These certificates are managed and vouched for by <em>Certificate
 * Authorities</em> (CAs).  CAs are services which create certificates by
 * placing data in the X.509 standard format and then digitally signing
 * that data.  Such signatures are quite difficult to forge.  CAs act as
 * trusted third parties, making introductions between agents who have no
 * direct knowledge of each other.  CA certificates are either signed by
 * themselves, or by some other CA such as a "root" CA.
 *
 * <P>RFC 1422 is very informative, though it does not describe much
 * of the recent work being done with X.509 certificates.  That includes
 * a 1996 version (X.509v3) and a variety of enhancements being made to
 * facilitate an explosion of personal certificates used as "Internet
 * Drivers' Licences", or with SET for credit card transactions.
 *
 * <P>More recent work includes the IETF PKIX Working Group efforts,
 * especially RFC2459.
 *
 * @author Dave Brownell
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @see X509CertInfo
 */
public class X509CertImpl extends sun.security.x509.X509CertImpl {

    /**
     * Default constructor.
     */
    public X509CertImpl() {
       super();
    }

    /**
     * Unmarshals a certificate from its encoded form, parsing the
     * encoded bytes.  This form of constructor is used by agents which
     * need to examine and use certificate contents.  That is, this is
     * one of the more commonly used constructors.  Note that the buffer
     * must include only a certificate, and no "garbage" may be left at
     * the end.  If you need to ignore data at the end of a certificate,
     * use another constructor.
     *
     * @param certData the encoded bytes, with no trailing padding.
     * @exception CertificateException on parsing and initialization errors.
     */
    public X509CertImpl(byte[] certData) throws CertificateException {
        super(certData);
    }

    /**
     * Throws an exception if the certificate was not signed using the
     * verification key provided.  Successfully verifying a certificate
     * does <em>not</em> indicate that one should trust the entity which
     * it represents.
     *
     * @param key the public key used for verification.
     * @param sigProvider the name of the provider.
     *
     * @exception NoSuchAlgorithmException on unsupported signature
     * algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchProviderException on incorrect provider.
     * @exception SignatureException on signature errors.
     * @exception CertificateException on encoding errors.
     */
    public synchronized void verify(PublicKey key, String sigProvider)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        if (sigProvider == null) {
            sigProvider = "";
        }
        try {
            Class<?> clazz = getClass().getSuperclass();
            Field verifiedPublicKeyField = clazz.getDeclaredField("verifiedPublicKey");
            verifiedPublicKeyField.setAccessible(true);
            PublicKey verifiedPublicKey = (PublicKey)verifiedPublicKeyField.get(this);
            Field verifiedProviderField = clazz.getDeclaredField("verifiedProvider");
            verifiedProviderField.setAccessible(true);
            String verifiedProvider = (String)verifiedProviderField.get(this);
            Field verificationResultField = clazz.getDeclaredField("verificationResult");
            verificationResultField.setAccessible(true);
            Field signedCertField = clazz.getDeclaredField("signedCert");
            signedCertField.setAccessible(true);

            if ((verifiedPublicKey != null) && verifiedPublicKey.equals(key)) {
                // this certificate has already been verified using
                // this public key. Make sure providers match, too.
                if (sigProvider.equals(verifiedProvider)) {
                    if (verificationResultField.getBoolean(this)) {
                        return;
                    } else {
                        throw new SignatureException("Signature does not match.");
                    }
                }
            }
            if (signedCertField.get(this) == null) {
                throw new CertificateEncodingException("Uninitialized certificate");
            }
            // Verify the signature ...
            Signature sigVerf = null;
            if (sigProvider.length() == 0) {
                sigVerf = Signature.getInstance(algId.getName());
            } else {
                sigVerf = Signature.getInstance(algId.getName(), sigProvider);
            }
            sigVerf.initVerify(key);

            // set parameters after Signature.initSign/initVerify call,
            // so the deferred provider selection happens when key is set
            try {
                SignatureUtil.specialSetParameter(sigVerf, getSigAlgParams());
            } catch (ProviderException e) {
                throw new CertificateException(e.getMessage(), e.getCause());
            } catch (InvalidAlgorithmParameterException e) {
                throw new CertificateException(e);
            }

            byte[] rawCert = info.getEncodedInfo();
            sigVerf.update(rawCert, 0, rawCert.length);

            // verify may throw SignatureException for invalid encodings, etc.
            boolean res = sigVerf.verify(signature);
            verificationResultField.setBoolean(this, res);
            verifiedPublicKeyField.set(this,key);
            verifiedProviderField.set(this, sigProvider);

            if (res == false) {
                throw new SignatureException("Signature does not match.");
            }
        }catch(IllegalArgumentException | IllegalAccessException | NoSuchFieldException e) {
            throw new SignatureException("Signature verification fails.");
        }
    }

    /**
     * Throws an exception if the certificate was not signed using the
     * verification key provided.  This method uses the signature verification
     * engine supplied by the specified provider. Note that the specified
     * Provider object does not have to be registered in the provider list.
     * Successfully verifying a certificate does <em>not</em> indicate that one
     * should trust the entity which it represents.
     *
     * @param key the public key used for verification.
     * @param sigProvider the provider.
     *
     * @exception NoSuchAlgorithmException on unsupported signature
     * algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception SignatureException on signature errors.
     * @exception CertificateException on encoding errors.
     */
    public synchronized void verify(PublicKey key, Provider sigProvider)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Class<?> clazz = getClass().getSuperclass();
        try {
            Field signedCertField = clazz.getDeclaredField("signedCert");
            signedCertField.setAccessible(true);
            if (signedCertField.get(this) == null) {
                throw new CertificateEncodingException("Uninitialized certificate");
            }
        }catch(IllegalArgumentException | IllegalAccessException | NoSuchFieldException e) {
            throw new SignatureException("Signature verification fails.");
        }

        // Verify the signature ...
        Signature sigVerf = null;
        if (sigProvider == null) {
            sigVerf = Signature.getInstance(algId.getName());
        } else {
            sigVerf = Signature.getInstance(algId.getName(), sigProvider);
        }
        sigVerf.initVerify(key);

        // set parameters after Signature.initSign/initVerify call,
        // so the deferred provider selection happens when key is set
        try {
            SignatureUtil.specialSetParameter(sigVerf, getSigAlgParams());
        } catch (ProviderException e) {
            throw new CertificateException(e.getMessage(), e.getCause());
        } catch (InvalidAlgorithmParameterException e) {
            throw new CertificateException(e);
        }

        byte[] rawCert = info.getEncodedInfo();
        sigVerf.update(rawCert, 0, rawCert.length);

        try {
            Field verifiedPublicKeyField = clazz.getDeclaredField("verifiedPublicKey");
            verifiedPublicKeyField.setAccessible(true);
            Field verificationResultField = clazz.getDeclaredField("verificationResult");
            verificationResultField.setAccessible(true);

            // verify may throw SignatureException for invalid encodings, etc.
            boolean res = sigVerf.verify(signature);
            verificationResultField.setBoolean(this, res);
            verifiedPublicKeyField.set(this,key);

            if (res == false) {
                throw new SignatureException("Signature does not match.");
            }
        }catch(IllegalArgumentException | IllegalAccessException | NoSuchFieldException e) {
            throw new SignatureException("Signature verification fails.");
        }
    }
}
