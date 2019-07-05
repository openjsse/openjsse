OpenJSSE
----------------------------------------------

----------------------------------------------------------------------------
OpenJSSE: A JSSE provider that supports TLS 1.3 on Java SE 8.

The OpenJSSE project was created to add support for TLS 1.3 to
existing Java 8 applications without requiring code changes, and to
provide a means to programmatically to code to TLS 1.3 and RSASSA-PSS
capabilities not directly available via the Java SE 8 APIs. 

When using the OpenJSSE JSSE provider, both clients and servers will
auto-negotiate TLS 1.3, unless explicitly configured otherwise, while
still including full support for all TLS behaviors found in Java SE 8.

The public API for OpenJSSE is located in the org.openjsse.javax.net.ssl
and org.openjsse.java.security.spec packages and is similar to the
Java SE 11 javax.net.ssl and java.security.spec package APIs. 

----
### Code origins and evolution

The project code is comprised primarily of a backport (to Java 8)
of the OpenJDK 11 implementations of various components that
together comprise of a TLS 1.3 JSSE provider. While small modification
were needed in order to make the code work on Java 8 JREs, the
structure of the OpenJDK 11 code has been kept mostly intact, with
associated packages placed under the org.openjsse.* namespace to
avoid collisions.

The code for this project is licensed under the OpenJDK GPLv2 + CPE
license, as described in the LICENSE file at the base of this repository
and in notices found in the various source files.
