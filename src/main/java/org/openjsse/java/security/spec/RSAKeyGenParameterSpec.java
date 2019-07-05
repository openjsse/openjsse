/*
 * Copyright (c) 1999, 2018, Oracle and/or its affiliates. All rights reserved.
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

package org.openjsse.java.security.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

/**
 * This class extends java.security.spec.RSAKeyGenParameterSpec class
 * to implement RSASSA-PSS signature algorithms
 */

public class RSAKeyGenParameterSpec extends  java.security.spec.RSAKeyGenParameterSpec {

    private final AlgorithmParameterSpec keyParams;

    /**
     * Constructs a new {@code RSAParameterSpec} object from the
     * given keysize and public-exponent value.
     *
     * @param keysize the modulus size (specified in number of bits)
     * @param publicExponent the public exponent
     */
    public RSAKeyGenParameterSpec(int keysize, BigInteger publicExponent) {
        this(keysize, publicExponent, null);
    }

    /**
     * Constructs a new {@code RSAKeyGenParameterSpec} object from the
     * given keysize, public-exponent value, and key parameters.
     *
     * @param keysize the modulus size (specified in number of bits)
     * @param publicExponent the public exponent
     * @param keyParams the key parameters, may be null
     * @since 11
     */
    public RSAKeyGenParameterSpec(int keysize, BigInteger publicExponent,
            AlgorithmParameterSpec keyParams) {
        super(keysize, publicExponent);
        this.keyParams = keyParams;
    }

    /**
     * Returns the parameters to be associated with key.
     *
     * @return the associated parameters, may be null if
     *         not present
     * @since 11
     */
    public AlgorithmParameterSpec getKeyParams() {
        return keyParams;
    }
}
