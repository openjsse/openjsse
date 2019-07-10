/*
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
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

package org.openjsse.sun.security.ssl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import sun.security.action.GetPropertyAction;
import org.openjsse.sun.security.util.HexDumpEncoder;
import sun.security.x509.*;

//JDK8 - modified
/**
 * Implementation of SSL logger.
 *
 * If the system property "javax.net.debug" is not defined, the debug logging
 * is turned off.  If the system property "javax.net.debug" is defined as
 * empty, the debug logger is specified by System.getLogger("javax.net.ssl"),
 * and applications can customize and configure the logger or use external
 * logging mechanisms.  If the system property "javax.net.debug" is defined
 * and non-empty, a private debug logger implemented in this class is used.
 */
public final class SSLLogger {
    private static final SSLConsoleLogger logger;
    private static final String property;
    public static final boolean isOn;

    //JDK8
    public enum Level {

            // for convenience, we're reusing java.util.logging.Level int values
            // the mapping logic in sun.util.logging.PlatformLogger depends
            // on this.
            /**
             * A marker to indicate that all levels are enabled.
             * This level {@linkplain #getSeverity() severity} is
             * {@link Integer#MIN_VALUE}.
             */
            ALL(Integer.MIN_VALUE),  // typically mapped to/from j.u.l.Level.ALL
            /**
             * {@code TRACE} level: usually used to log diagnostic information.
             * This level {@linkplain #getSeverity() severity} is
             * {@code 400}.
             */
            TRACE(400),   // typically mapped to/from j.u.l.Level.FINER
            /**
             * {@code DEBUG} level: usually used to log debug information traces.
             * This level {@linkplain #getSeverity() severity} is
             * {@code 500}.
             */
            DEBUG(500),   // typically mapped to/from j.u.l.Level.FINEST/FINE/CONFIG
            /**
             * {@code INFO} level: usually used to log information messages.
             * This level {@linkplain #getSeverity() severity} is
             * {@code 800}.
             */
            INFO(800),    // typically mapped to/from j.u.l.Level.INFO
            /**
             * {@code WARNING} level: usually used to log warning messages.
             * This level {@linkplain #getSeverity() severity} is
             * {@code 900}.
             */
            WARNING(900), // typically mapped to/from j.u.l.Level.WARNING
            /**
             * {@code ERROR} level: usually used to log error messages.
             * This level {@linkplain #getSeverity() severity} is
             * {@code 1000}.
             */
            ERROR(1000),  // typically mapped to/from j.u.l.Level.SEVERE
            /**
             * A marker to indicate that all levels are disabled.
             * This level {@linkplain #getSeverity() severity} is
             * {@link Integer#MAX_VALUE}.
             */
            OFF(Integer.MAX_VALUE);  // typically mapped to/from j.u.l.Level.OFF

            private final int severity;

            private Level(int severity) {
                this.severity = severity;
            }

            /**
             * Returns the name of this level.
             * @return this level {@linkplain #name()}.
             */
            public final String getName() {
                return name();
            }

            /**
             * Returns the severity of this level.
             * A higher severity means a more severe condition.
             * @return this level severity.
             */
            public final int getSeverity() {
                return severity;
            }
        }

    static {
        String p = GetPropertyAction.privilegedGetProperty("javax.net.debug");
        if (p != null) {
            if (p.isEmpty()) {
                property = "";
                logger = new SSLConsoleLogger("javax.net.ssl", p);
            } else {
                property = p.toLowerCase(Locale.ENGLISH);
                if (property.equals("help")) {
                    help();
                }

                logger = new SSLConsoleLogger("javax.net.ssl", p);
            }
            isOn = true;
        } else {
            property = null;
            logger = null;
            isOn = false;
        }
    }

    private static void help() {
        System.err.println();
        System.err.println("help           print the help messages");
        System.err.println("expand         expand debugging information");
        System.err.println();
        System.err.println("all            turn on all debugging");
        System.err.println("ssl            turn on ssl debugging");
        System.err.println();
        System.err.println("The following can be used with ssl:");
        System.err.println("\trecord       enable per-record tracing");
        System.err.println("\thandshake    print each handshake message");
        System.err.println("\tkeygen       print key generation data");
        System.err.println("\tsession      print session activity");
        System.err.println("\tdefaultctx   print default SSL initialization");
        System.err.println("\tsslctx       print SSLContext tracing");
        System.err.println("\tsessioncache print session cache tracing");
        System.err.println("\tkeymanager   print key manager tracing");
        System.err.println("\ttrustmanager print trust manager tracing");
        System.err.println("\tpluggability print pluggability tracing");
        System.err.println();
        System.err.println("\thandshake debugging can be widened with:");
        System.err.println("\tdata         hex dump of each handshake message");
        System.err.println("\tverbose      verbose handshake message printing");
        System.err.println();
        System.err.println("\trecord debugging can be widened with:");
        System.err.println("\tplaintext    hex dump of record plaintext");
        System.err.println("\tpacket       print raw SSL/TLS packets");
        System.err.println();
        System.exit(0);
    }

    /**
     * Return true if the "javax.net.debug" property contains the
     * debug check points, or System.Logger is used.
     */
    public static boolean isOn(String checkPoints) {
        if (property == null) {              // debugging is turned off
            return false;
        } else if (property.isEmpty()) {     // use System.Logger
            return true;
        }                                   // use provider logger

        String[] options = checkPoints.split(",");
        for (String option : options) {
            option = option.trim();
            if (!SSLLogger.hasOption(option)) {
                return false;
            }
        }

        return true;
    }

    private static boolean hasOption(String option) {
        option = option.toLowerCase(Locale.ENGLISH);
        if (property.contains("all")) {
            return true;
        } else {
            int offset = property.indexOf("ssl");
            if (offset != -1 && property.indexOf("sslctx", offset) != -1) {
                // don't enable data and plaintext options by default
                if (!(option.equals("data")
                        || option.equals("packet")
                        || option.equals("plaintext"))) {
                    return true;
                }
            }
        }

        return property.contains(option);
    }

    public static void severe(String msg, Object... params) {
        SSLLogger.log(Level.ERROR, msg, params);
    }

    public static void warning(String msg, Object... params) {
        SSLLogger.log(Level.WARNING, msg, params);
    }

    public static void info(String msg, Object... params) {
        SSLLogger.log(Level.INFO, msg, params);
    }

    public static void fine(String msg, Object... params) {
        SSLLogger.log(Level.DEBUG, msg, params);
    }

    public static void finer(String msg, Object... params) {
        SSLLogger.log(Level.TRACE, msg, params);
    }

    public static void finest(String msg, Object... params) {
        SSLLogger.log(Level.ALL, msg, params);
    }

    private static void log(Level level, String msg, Object... params) {
        if (logger.isLoggable(level)) {
            if (params == null || params.length == 0) {
                logger.log(level, msg);
            } else {
                try {
                    String formatted =
                            SSLSimpleFormatter.formatParameters(params);
                    logger.log(level, msg, formatted);
                } catch (Exception exp) {
                    // ignore it, just for debugging.
                }
            }
        }
    }

    static String toString(Object... params) {
        try {
            return SSLSimpleFormatter.formatParameters(params);
        } catch (Exception exp) {
            return "unexpected exception thrown: " + exp.getMessage();
        }
    }

    private static class SSLConsoleLogger {
        private final String loggerName;
        private final boolean useCompactFormat;

        SSLConsoleLogger(String loggerName, String options) {
            this.loggerName = loggerName;
            options = options.toLowerCase(Locale.ENGLISH);
            this.useCompactFormat = !options.contains("expand");
        }

        public String getName() {
            return loggerName;
        }

        public boolean isLoggable(Level level) {
            return (level != Level.OFF);
        }

        public void log(Level level,
                String message, Object... params) {
            if (isLoggable(level)) {
                try {
                    String formatted =
                        SSLSimpleFormatter.format(this, level, message, params);
                    System.err.write(formatted.getBytes("UTF-8"));
                } catch (Exception exp) {
                    // ignore it, just for debugging.
                }
            }
        }

        public void log(Level level,
                ResourceBundle rb, String message, Throwable thrwbl) {
            if (isLoggable(level)) {
                try {
                    String formatted =
                        SSLSimpleFormatter.format(this, level, message, thrwbl);
                    System.err.write(formatted.getBytes("UTF-8"));
                } catch (Exception exp) {
                    // ignore it, just for debugging.
                }
            }
        }

        public void log(Level level,
                ResourceBundle rb, String message, Object... params) {
            if (isLoggable(level)) {
                try {
                    String formatted =
                        SSLSimpleFormatter.format(this, level, message, params);
                    System.err.write(formatted.getBytes("UTF-8"));
                } catch (Exception exp) {
                    // ignore it, just for debugging.
                }
            }
        }
    }

    private static class SSLSimpleFormatter {
        private static final ThreadLocal<SimpleDateFormat> dateFormat =
            new ThreadLocal<SimpleDateFormat>() {
                @Override protected SimpleDateFormat initialValue() {
                    return new SimpleDateFormat(
                            "yyyy-MM-dd kk:mm:ss.SSS z", Locale.ENGLISH);
                }
            };

        private static final MessageFormat basicCertFormat = new MessageFormat(
                "\"version\"            : \"v{0}\",\n" +
                "\"serial number\"      : \"{1}\",\n" +
                "\"signature algorithm\": \"{2}\",\n" +
                "\"issuer\"             : \"{3}\",\n" +
                "\"not before\"         : \"{4}\",\n" +
                "\"not  after\"         : \"{5}\",\n" +
                "\"subject\"            : \"{6}\",\n" +
                "\"subject public key\" : \"{7}\"\n",
                Locale.ENGLISH);

        private static final MessageFormat extendedCertFormart =
            new MessageFormat(
                "\"version\"            : \"v{0}\",\n" +
                "\"serial number\"      : \"{1}\",\n" +
                "\"signature algorithm\": \"{2}\",\n" +
                "\"issuer\"             : \"{3}\",\n" +
                "\"not before\"         : \"{4}\",\n" +
                "\"not  after\"         : \"{5}\",\n" +
                "\"subject\"            : \"{6}\",\n" +
                "\"subject public key\" : \"{7}\",\n" +
                "\"extensions\"         : [\n" +
                "{8}\n" +
                "]\n",
                Locale.ENGLISH);

        //
        // private static MessageFormat certExtFormat = new MessageFormat(
        //         "{0} [{1}] '{'\n" +
        //         "  critical: {2}\n" +
        //         "  value: {3}\n" +
        //         "'}'",
        //         Locale.ENGLISH);
        //

        private static final MessageFormat messageFormatNoParas =
            new MessageFormat(
                "'{'\n" +
                "  \"logger\"      : \"{0}\",\n" +
                "  \"level\"       : \"{1}\",\n" +
                "  \"thread id\"   : \"{2}\",\n" +
                "  \"thread name\" : \"{3}\",\n" +
                "  \"time\"        : \"{4}\",\n" +
                "  \"caller\"      : \"{5}\",\n" +
                "  \"message\"     : \"{6}\"\n" +
                "'}'\n",
                Locale.ENGLISH);

        private static final MessageFormat messageCompactFormatNoParas =
            new MessageFormat(
                "{0}|{1}|{2}|{3}|{4}|{5}|{6}\n",
                Locale.ENGLISH);

        private static final MessageFormat messageFormatWithParas =
            new MessageFormat(
                "'{'\n" +
                "  \"logger\"      : \"{0}\",\n" +
                "  \"level\"       : \"{1}\",\n" +
                "  \"thread id\"   : \"{2}\",\n" +
                "  \"thread name\" : \"{3}\",\n" +
                "  \"time\"        : \"{4}\",\n" +
                "  \"caller\"      : \"{5}\",\n" +
                "  \"message\"     : \"{6}\",\n" +
                "  \"specifics\"   : [\n" +
                "{7}\n" +
                "  ]\n" +
                "'}'\n",
                Locale.ENGLISH);

        private static final MessageFormat messageCompactFormatWithParas =
            new MessageFormat(
                "{0}|{1}|{2}|{3}|{4}|{5}|{6} (\n" +
                "{7}\n" +
                ")\n",
                Locale.ENGLISH);

        private static final MessageFormat keyObjectFormat = new MessageFormat(
                "\"{0}\" : '{'\n" +
                "{1}" +
                "'}'\n",
                Locale.ENGLISH);

        // INFO: [TH: 123450] 2011-08-20 23:12:32.3225 PDT
        //     log message
        //     log message
        //     ...
        private static String format(SSLConsoleLogger logger, Level level,
                    String message, Object ... parameters) {

            if (parameters == null || parameters.length == 0) {
                Object[] messageFields = {
                    logger.loggerName,
                    level.getName(),
                    Utilities.toHexString(Thread.currentThread().getId()),
                    Thread.currentThread().getName(),
                    dateFormat.get().format(new Date(System.currentTimeMillis())),
                    formatCaller(),
                    message
                };

                if (logger.useCompactFormat) {
                    return messageCompactFormatNoParas.format(messageFields);
                } else {
                    return messageFormatNoParas.format(messageFields);
                }
            }

            Object[] messageFields = {
                    logger.loggerName,
                    level.getName(),
                    Utilities.toHexString(Thread.currentThread().getId()),
                    Thread.currentThread().getName(),
                    dateFormat.get().format(new Date(System.currentTimeMillis())),
                    formatCaller(),
                    message,
                    (logger.useCompactFormat ?
                        formatParameters(parameters) :
                        Utilities.indent(formatParameters(parameters)))
                };

            if (logger.useCompactFormat) {
                return messageCompactFormatWithParas.format(messageFields);
            } else {
                return messageFormatWithParas.format(messageFields);
            }
        }

        //JDK8
        private static String formatCaller() {
            StackTraceElement[] stElements = Thread.currentThread().getStackTrace();
            for (int i=1; i<stElements.length; i++) {
                StackTraceElement ste = stElements[i];
                if (!ste.getClassName().startsWith(SSLLogger.class.getName()) &&
                    !ste.getClassName().startsWith("java.lang.System")) {
                   return ste.getFileName() + ":" + ste.getLineNumber();
                }
            }
            return "unknown caller";
        }

        private static String formatParameters(Object ... parameters) {
            StringBuilder builder = new StringBuilder(512);
            boolean isFirst = true;
            for (Object parameter : parameters) {
                if (isFirst) {
                    isFirst = false;
                } else {
                    builder.append(",\n");
                }

                if (parameter instanceof Throwable) {
                    builder.append(formatThrowable((Throwable)parameter));
                } else if (parameter instanceof Certificate) {
                    builder.append(formatCertificate((Certificate)parameter));
                } else if (parameter instanceof ByteArrayInputStream) {
                    builder.append(formatByteArrayInputStream(
                        (ByteArrayInputStream)parameter));
                } else if (parameter instanceof ByteBuffer) {
                    builder.append(formatByteBuffer((ByteBuffer)parameter));
                } else if (parameter instanceof byte[]) {
                    builder.append(formatByteArrayInputStream(
                        new ByteArrayInputStream((byte[])parameter)));
                } else if (parameter instanceof Map.Entry) {
                    @SuppressWarnings("unchecked")
                    Map.Entry<String, ?> mapParameter =
                        (Map.Entry<String, ?>)parameter;
                    builder.append(formatMapEntry(mapParameter));
                } else {
                    builder.append(formatObject(parameter));
                }
            }

            return builder.toString();
        }

        // "throwable": {
        //   ...
        // }
        private static String formatThrowable(Throwable throwable) {
            StringBuilder builder = new StringBuilder(512);
            ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            try (PrintStream out = new PrintStream(bytesOut)) {
                throwable.printStackTrace(out);
                builder.append(Utilities.indent(bytesOut.toString()));
            }
            Object[] fields = {
                    "throwable",
                    builder.toString()
                };

            return keyObjectFormat.format(fields);
        }

        // "certificate": {
        //   ...
        // }
        private static String formatCertificate(Certificate certificate) {

            if (!(certificate instanceof X509Certificate)) {
                return Utilities.indent(certificate.toString());
            }

            StringBuilder builder = new StringBuilder(512);
            try {
                X509CertImpl x509 =
                    X509CertImpl.toImpl((X509Certificate)certificate);
                X509CertInfo certInfo =
                        (X509CertInfo)x509.get(X509CertImpl.NAME + "." +
                                                       X509CertImpl.INFO);
                CertificateExtensions certExts = (CertificateExtensions)
                        certInfo.get(X509CertInfo.EXTENSIONS);
                if (certExts == null) {
                    Object[] certFields = {
                        x509.getVersion(),
                        Utilities.toHexString(
                                x509.getSerialNumber().toByteArray()),
                        x509.getSigAlgName(),
                        x509.getIssuerX500Principal().toString(),
                        dateFormat.get().format(x509.getNotBefore()),
                        dateFormat.get().format(x509.getNotAfter()),
                        x509.getSubjectX500Principal().toString(),
                        x509.getPublicKey().getAlgorithm()
                        };
                    builder.append(Utilities.indent(
                            basicCertFormat.format(certFields)));
                } else {
                    StringBuilder extBuilder = new StringBuilder(512);
                    boolean isFirst = true;
                    for (Extension certExt : certExts.getAllExtensions()) {
                        if (isFirst) {
                            isFirst = false;
                        } else {
                            extBuilder.append(",\n");
                        }
                        extBuilder.append("{\n" +
                            Utilities.indent(certExt.toString()) + "\n}");
                    }
                    Object[] certFields = {
                        x509.getVersion(),
                        Utilities.toHexString(
                                x509.getSerialNumber().toByteArray()),
                        x509.getSigAlgName(),
                        x509.getIssuerX500Principal().toString(),
                        dateFormat.get().format(x509.getNotBefore()),
                        dateFormat.get().format(x509.getNotAfter()),
                        x509.getSubjectX500Principal().toString(),
                        x509.getPublicKey().getAlgorithm(),
                        Utilities.indent(extBuilder.toString())
                        };
                    builder.append(Utilities.indent(
                            extendedCertFormart.format(certFields)));
                }
            } catch (Exception ce) {
                // ignore the exception
            }

            Object[] fields = {
                    "certificate",
                    builder.toString()
                };

            return Utilities.indent(keyObjectFormat.format(fields));
        }

        private static String formatByteArrayInputStream(
                ByteArrayInputStream bytes) {
            StringBuilder builder = new StringBuilder(512);

            try (ByteArrayOutputStream bytesOut = new ByteArrayOutputStream()) {
                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                hexEncoder.encodeBuffer(bytes, bytesOut);

                builder.append(Utilities.indent(bytesOut.toString()));
            } catch (IOException ioe) {
                // ignore it, just for debugging.
            }

            return builder.toString();
        }

        private static String formatByteBuffer(ByteBuffer byteBuffer) {
            StringBuilder builder = new StringBuilder(512);
            try (ByteArrayOutputStream bytesOut = new ByteArrayOutputStream()) {
                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                hexEncoder.encodeBuffer(byteBuffer.duplicate(), bytesOut);
                builder.append(Utilities.indent(bytesOut.toString()));
            } catch (IOException ioe) {
                // ignore it, just for debugging.
            }

            return builder.toString();
        }

        private static String formatMapEntry(Map.Entry<String, ?> entry) {
            String key = entry.getKey();
            Object value = entry.getValue();

            String formatted;
            if (value instanceof String) {
                // "key": "value"
                formatted = "\"" + key + "\": \"" + (String)value + "\"";
            } else if (value instanceof String[]) {
                // "key": [ "string a",
                //          "string b",
                //          "string c"
                //        ]
                StringBuilder builder = new StringBuilder(512);
                String[] strings = (String[])value;
                builder.append("\"" + key + "\": [\n");
                for (String string : strings) {
                    builder.append("      \"" + string + "\"");
                    if (string != strings[strings.length - 1]) {
                        builder.append(",");
                    }
                    builder.append("\n");
                }
                builder.append("      ]");

                formatted = builder.toString();
            } else if (value instanceof byte[]) {
                formatted = "\"" + key + "\": \"" +
                    Utilities.toHexString((byte[])value) + "\"";
            } else if (value instanceof Byte) {
                formatted = "\"" + key + "\": \"" +
                    Utilities.toHexString((byte)value) + "\"";
            } else {
                formatted = "\"" + key + "\": " +
                    "\"" + value.toString() + "\"";
            }

            return Utilities.indent(formatted);
        }

        private static String formatObject(Object obj) {
            return obj.toString();
        }
    }
}
