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

import javax.net.ssl.*;
import java.io.IOException;
import java.net.*;
import java.security.NoSuchAlgorithmException;

/*
 * Application below uses OpenJSSE provider to set up connection to
 * external https server. On completion application prints information
 * about established connection : used protocol, cipher suite and peer DN.
 */
public class HttpsClient {

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("No server url provided");
            return;
        }
        try {
            // Create URLConnection from https server adress
            URL url = new URL(args[0]);
            new HttpsClient().connect(url);
        } catch (MalformedURLException e) {
            System.out.println("Malformed URL " + args[0]);
        }
    }

    private void connect(URL url) {
        try {
            // Create URLConnection from https server adress
            HttpsURLConnection con =
                    (HttpsURLConnection) url.openConnection();
            SSLContext sslContext = SSLContext.getDefault();
            // Set custom ssl socket factory and handshake listener
            ((HttpsURLConnection) con).setSSLSocketFactory(
                    new CustomSSLSocketFactory(sslContext.getSocketFactory(),
                            new CustomHandshakeCompletedListener()));
            // real connection to server
            System.out.println("Connect to " + url + " using "
                    + sslContext.getProvider().getName() + " provider");
            con.connect();
            System.out.println("Response Code= " + con.getResponseCode());
        } catch (IOException |
                NoSuchAlgorithmException e) {
            System.out.println("Connection failed : " + e.getMessage());
            e.printStackTrace();

        }
    }

    public class CustomHandshakeCompletedListener
            implements HandshakeCompletedListener {
        // Overwrite handshakeCompleted event listener to print info upon
        // connection completion
        @Override
        public void handshakeCompleted(HandshakeCompletedEvent event) {
            SSLSession session = event.getSession();
            String peerDN = null;
            try {
                peerDN = session.getPeerPrincipal().getName();
            } catch (SSLPeerUnverifiedException e) {
            }
            System.out.println("Protocol     = " + session.getProtocol());
            System.out.println("Cipher Suite = " + session.getCipherSuite());
            System.out.println("Peer DN      = " + peerDN);
        }
    }

    /*
     * Custom SSLSocketFactory class
     * This class is used to overwrite default handshake listener
     */
    public class CustomSSLSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory factory;
        private HandshakeCompletedListener listener;

        public CustomSSLSocketFactory(
                SSLSocketFactory factory, HandshakeCompletedListener listener) {
            this.factory = factory;
            this.listener = listener;
        }

        @Override
        public Socket createSocket() throws IOException {
            SSLSocket socket = (SSLSocket) factory.createSocket();

            if (null != listener) {
                socket.addHandshakeCompletedListener(listener);
            }

            return socket;
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return factory.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return factory.getSupportedCipherSuites();
        }

        @Override
        public Socket createSocket(Socket s, String host,
                                   int port, boolean autoClose)
                throws IOException {
            throw new SocketException("Not implemented");
        }

        @Override
        public Socket createSocket(InetAddress address, int port,
                                   InetAddress clientAddress, int clientPort) throws IOException {
            throw new SocketException("Not implemented");
        }

        @Override
        public Socket createSocket(String host, int port)
                throws IOException {
            throw new SocketException("Not implemented");
        }

        @Override
        public Socket createSocket(InetAddress address, int port)
                throws IOException {
            throw new SocketException("Not implemented");
        }

        @Override
        public Socket createSocket(String host, int port,
                                   InetAddress clientAddress, int clientPort)
                throws IOException {
            throw new SocketException("Not implemented");
        }
    }
}
