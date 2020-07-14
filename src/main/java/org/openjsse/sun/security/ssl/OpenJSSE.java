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

import java.security.*;
import sun.security.action.GetPropertyAction;
import sun.security.x509.AlgorithmId;
import sun.security.util.ObjectIdentifier;
import java.lang.reflect.Field;
import java.util.Map;

/**
 * The JSSE provider.
 *
 * The RSA implementation has been removed from JSSE, but we still need to
 * register the same algorithms for compatibility. We just point to the RSA
 * implementation in the SunRsaSign provider. This works because all classes
 * are in the bootclasspath and therefore loaded by the same classloader.
 *
 * OpenJSSE now supports an experimental FIPS compliant mode when used with an
 * appropriate FIPS certified crypto provider. In FIPS mode, we:
 *  . allow only TLS 1.0 or later
 *  . allow only FIPS approved ciphersuites
 *  . perform all crypto in the FIPS crypto provider
 *
 * It is currently not possible to use both FIPS compliant OpenJSSE and
 * standard JSSE at the same time because of the various static data structures
 * we use.
 *
 * However, we do want to allow FIPS mode to be enabled at runtime and without
 * editing the java.security file. That means we need to allow
 * Security.removeProvider("OpenJSSE") to work, which creates an instance of
 * this class in non-FIPS mode. That is why we delay the selection of the mode
 * as long as possible. This is until we open an SSL/TLS connection and the
 * data structures need to be initialized or until OpenJSSE is initialized in
 * FIPS mode.
 *
 */
public abstract class OpenJSSE extends Provider {
    public static final double PROVIDER_VER;

    private static final long serialVersionUID = 3231825739635378733L;

    private static String info;

    private static String fipsInfo =
        "JDK JSSE provider (FIPS mode, crypto provider ";

    // tri-valued flag:
    // null  := no final decision made
    // false := data structures initialized in non-FIPS mode
    // true  := data structures initialized in FIPS mode
    private static Boolean fips;

    // the FIPS certificate crypto provider that we use to perform all crypto
    // operations. null in non-FIPS mode
    static java.security.Provider cryptoProvider;

    static {
        PROVIDER_VER = Double.parseDouble(System.getProperty("java.specification.version"));
        info = "JDK JSSE provider" +
               "(PKCS12, SunX509/PKIX key/trust factories, " +
               "SSLv3/TLSv1/TLSv1.1/TLSv1.2/TLSv1.3)";
    }
    protected static synchronized boolean isFIPS() {
        if (fips == null) {
            fips = false;
        }
        return fips;
    }

    // ensure we can use FIPS mode using the specified crypto provider.
    // enable FIPS mode if not already enabled.
    private static synchronized void ensureFIPS(java.security.Provider p) {
        if (fips == null) {
            fips = true;
            cryptoProvider = p;
        } else {
            if (fips == false) {
                throw new ProviderException
                    ("OpenJSSE already initialized in non-FIPS mode");
            }
            if (cryptoProvider != p) {
                throw new ProviderException
                    ("OpenJSSE already initialized with FIPS crypto provider "
                    + cryptoProvider);
            }
        }
    }

    // standard constructor
    @SuppressWarnings( "deprecation" )
    protected OpenJSSE() {
        super("OpenJSSE", PROVIDER_VER, info);
        subclassCheck();
        if (Boolean.TRUE.equals(fips)) {
            throw new ProviderException
                ("OpenJSSE is already initialized in FIPS mode");
        }
        registerAlgorithms(false);
    }

    // preferred constructor to enable FIPS mode at runtime
    protected OpenJSSE(java.security.Provider cryptoProvider){
        this(checkNull(cryptoProvider), cryptoProvider.getName());
    }

    // constructor to enable FIPS mode from java.security file
    protected OpenJSSE(String cryptoProvider){
        this(null, checkNull(cryptoProvider));
    }

    private static <T> T checkNull(T t) {
        if (t == null) {
            throw new ProviderException("cryptoProvider must not be null");
        }
        return t;
    }

    @SuppressWarnings( "deprecation" )
    private OpenJSSE(java.security.Provider cryptoProvider,
            String providerName) {
        super("OpenJSSE", PROVIDER_VER, fipsInfo + providerName + ")");
        subclassCheck();
        if (cryptoProvider == null) {
            // Calling Security.getProvider() will cause other providers to be
            // loaded. That is not good but unavoidable here.
            cryptoProvider = Security.getProvider(providerName);
            if (cryptoProvider == null) {
                throw new ProviderException
                    ("Crypto provider not installed: " + providerName);
            }
        }
        ensureFIPS(cryptoProvider);
        registerAlgorithms(true);
    }

    @SuppressWarnings("unchecked")
    private void registerAlgorithms(final boolean isfips) {
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                doRegister(isfips);
                return null;
            }
        });
    }

    private void doRegister(boolean isfips) {
        if (isfips == false) {
            put("KeyFactory.RSA",
                "sun.security.rsa.RSAKeyFactory$Legacy");
            put("Alg.Alias.KeyFactory.1.2.840.113549.1.1", "RSA");
            put("Alg.Alias.KeyFactory.OID.1.2.840.113549.1.1", "RSA");

            put("KeyPairGenerator.RSA",
                "sun.security.rsa.RSAKeyPairGenerator$Legacy");
            put("Alg.Alias.KeyPairGenerator.1.2.840.113549.1.1", "RSA");
            put("Alg.Alias.KeyPairGenerator.OID.1.2.840.113549.1.1", "RSA");

            put("Signature.MD2withRSA",
                "sun.security.rsa.RSASignature$MD2withRSA");
            put("Alg.Alias.Signature.1.2.840.113549.1.1.2", "MD2withRSA");
            put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.2",
                "MD2withRSA");

            put("Signature.MD5withRSA",
                "sun.security.rsa.RSASignature$MD5withRSA");
            put("Alg.Alias.Signature.1.2.840.113549.1.1.4", "MD5withRSA");
            put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.4",
                "MD5withRSA");

            put("Signature.SHA1withRSA",
                "sun.security.rsa.RSASignature$SHA1withRSA");
            put("Alg.Alias.Signature.1.2.840.113549.1.1.5", "SHA1withRSA");
            put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5",
                "SHA1withRSA");
            put("Alg.Alias.Signature.1.3.14.3.2.29", "SHA1withRSA");
            put("Alg.Alias.Signature.OID.1.3.14.3.2.29", "SHA1withRSA");

        }
        put("Signature.MD5andSHA1withRSA",
            "sun.security.ssl.RSASignature");

        put("Cipher.ChaCha20",
            "org.openjsse.com.sun.crypto.provider.ChaCha20Cipher$ChaCha20Only");
        put("Cipher.ChaCha20 SupportedKeyFormats", "RAW");
        put("Cipher.ChaCha20-Poly1305",
            "org.openjsse.com.sun.crypto.provider.ChaCha20Cipher$ChaCha20Poly1305");
        put("Cipher.ChaCha20-Poly1305 SupportedKeyFormats", "RAW");
        put("Alg.Alias.Cipher.1.2.840.113549.1.9.16.3.18", "ChaCha20-Poly1305");
        put("Alg.Alias.Cipher.OID.1.2.840.113549.1.9.16.3.18", "ChaCha20-Poly1305");

        put("KeyGenerator.ChaCha20",
            "org.openjsse.com.sun.crypto.provider.KeyGeneratorCore$ChaCha20KeyGenerator");

        put("AlgorithmParameters.ChaCha20-Poly1305",
            "org.openjsse.com.sun.crypto.provider.ChaCha20Poly1305Parameters");

        put("KeyManagerFactory.SunX509",
            "org.openjsse.sun.security.ssl.KeyManagerFactoryImpl$SunX509");
        put("KeyManagerFactory.NewSunX509",
            "org.openjsse.sun.security.ssl.KeyManagerFactoryImpl$X509");
        put("Alg.Alias.KeyManagerFactory.PKIX", "NewSunX509");

        put("TrustManagerFactory.SunX509",
            "org.openjsse.sun.security.ssl.TrustManagerFactoryImpl$SimpleFactory");
        put("TrustManagerFactory.PKIX",
            "org.openjsse.sun.security.ssl.TrustManagerFactoryImpl$PKIXFactory");
        put("Alg.Alias.TrustManagerFactory.SunPKIX", "PKIX");
        put("Alg.Alias.TrustManagerFactory.X509", "PKIX");
        put("Alg.Alias.TrustManagerFactory.X.509", "PKIX");

        put("SSLContext.TLSv1",
            "org.openjsse.sun.security.ssl.SSLContextImpl$TLS10Context");
        put("SSLContext.TLSv1.1",
            "org.openjsse.sun.security.ssl.SSLContextImpl$TLS11Context");
        put("SSLContext.TLSv1.2",
            "org.openjsse.sun.security.ssl.SSLContextImpl$TLS12Context");
        put("SSLContext.TLSv1.3",
            "org.openjsse.sun.security.ssl.SSLContextImpl$TLS13Context");
        put("SSLContext.TLS",
            "org.openjsse.sun.security.ssl.SSLContextImpl$TLSContext");
        if (isfips == false) {
            put("Alg.Alias.SSLContext.SSL", "TLS");
            put("Alg.Alias.SSLContext.SSLv3", "TLSv1");
        }

        put("SSLContext.Default",
            "org.openjsse.sun.security.ssl.SSLContextImpl$DefaultSSLContext");

        /*
         * KeyStore
         */
        put("KeyStore.PKCS12",
            "sun.security.pkcs12.PKCS12KeyStore");

        /*
         * SSL/TLS mechanisms
         *
         * These are strictly internal implementations and may
         * be changed at any time.  These names were chosen
         * because PKCS11/SunPKCS11 does not yet have TLS1.2
         * mechanisms, and it will cause calls to come here.
         */
        put("KeyGenerator.SunTlsPrf",
                "org.openjsse.com.sun.crypto.provider.TlsPrfGenerator$V10");
        put("KeyGenerator.SunTls12Prf",
                "org.openjsse.com.sun.crypto.provider.TlsPrfGenerator$V12");

        put("KeyGenerator.SunTlsMasterSecret",
            "org.openjsse.com.sun.crypto.provider.TlsMasterSecretGenerator");
        put("Alg.Alias.KeyGenerator.SunTls12MasterSecret",
            "SunTlsMasterSecret");
        put("Alg.Alias.KeyGenerator.SunTlsExtendedMasterSecret",
            "SunTlsMasterSecret");

        put("KeyGenerator.SunTlsKeyMaterial",
            "org.openjsse.com.sun.crypto.provider.TlsKeyMaterialGenerator");
        put("Alg.Alias.KeyGenerator.SunTls12KeyMaterial",
            "SunTlsKeyMaterial");

        put("KeyGenerator.SunTlsRsaPremasterSecret",
            "org.openjsse.com.sun.crypto.provider.TlsRsaPremasterSecretGenerator");
        put("Alg.Alias.KeyGenerator.SunTls12RsaPremasterSecret",
            "SunTlsRsaPremasterSecret");

        if (PROVIDER_VER == 1.8d) {
            put("MessageDigest.SHA3-224", "org.openjsse.sun.security.provider.SHA3$SHA224");
            put("MessageDigest.SHA3-256", "org.openjsse.sun.security.provider.SHA3$SHA256");
            put("MessageDigest.SHA3-384", "org.openjsse.sun.security.provider.SHA3$SHA384");
            put("MessageDigest.SHA3-512", "org.openjsse.sun.security.provider.SHA3$SHA512");
        }

        // aliases
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.7", "SHA3-224");
        put("Alg.Alias.MessageDigest.OID.2.16.840.1.101.3.4.2.7",
                "SHA3-224");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.8", "SHA3-256");
        put("Alg.Alias.MessageDigest.OID.2.16.840.1.101.3.4.2.8",
                "SHA3-256");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.9", "SHA3-384");
        put("Alg.Alias.MessageDigest.OID.2.16.840.1.101.3.4.2.9",
                "SHA3-384");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.10", "SHA3-512");
        put("Alg.Alias.MessageDigest.OID.2.16.840.1.101.3.4.2.10",
                "SHA3-512");
        }

    // com.sun.net.ssl.internal.ssl.Provider has been deprecated since JDK 9
    @SuppressWarnings("deprecation")
    private void subclassCheck() {
        if (getClass() != org.openjsse.net.ssl.OpenJSSE.class) {
            throw new AssertionError("Illegal subclass: " + getClass());
        }
    }

    @Override
    @SuppressWarnings("deprecation")
    protected final void finalize() throws Throwable {
        // empty
        super.finalize();
    }

    @SuppressWarnings("cast")
    private static ObjectIdentifier oid(int ... values) {
        return (ObjectIdentifier)AccessController.doPrivileged(new PrivilegedAction<ObjectIdentifier>() {
            @Override
            public ObjectIdentifier run() {
                return ObjectIdentifier.newInternal(values);
            }
        });
    }
}
