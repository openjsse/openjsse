open module org.openjsse {
    provides java.security.Provider with org.openjsse.net.ssl.OpenJSSE;
    requires jdk.unsupported;
    exports org.openjsse.net.ssl;
    exports org.openjsse.javax.net.ssl;
    exports org.openjsse.java.security.spec;
    exports org.openjsse.util;
}