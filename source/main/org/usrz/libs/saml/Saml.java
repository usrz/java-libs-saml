/* ========================================================================== *
 * Copyright 2014 USRZ.com and Pier Paolo Fumagalli                           *
 * -------------------------------------------------------------------------- *
 * Licensed under the Apache License, Version 2.0 (the "License");            *
 * you may not use this file except in compliance with the License.           *
 * You may obtain a copy of the License at                                    *
 *                                                                            *
 *  http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing, software        *
 * distributed under the License is distributed on an "AS IS" BASIS,          *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
 * See the License for the specific language governing permissions and        *
 * limitations under the License.                                             *
 * ========================================================================== */
package org.usrz.libs.saml;

import static com.google.common.collect.Iterators.singletonIterator;

import java.net.URI;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.namespace.NamespaceContext;

/**
 * A class envelping all the constants used by our <i>SAML</i> implementation.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public final class Saml {

    private Saml() {
        throw new IllegalStateException("Do not construct");
    }

    /* ====================================================================== */

    /** The version of the <i>SAML</i> specification: <code>2.0</code> */
    public static final String VERSION = "2.0";

    /* ====================================================================== */

    /**
     * The supported <i>SAML Protocol Bindings</i>
     *
     * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
     */
    public enum ProtocolBinding {
        /** Redirect: <code>urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect</code> */
        HTTP_REDIRECT("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),
        /** POST: <code>urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST</code> */
        HTTP_POST("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

        private final URI uri;

        private ProtocolBinding(String uri) {
            this.uri = URI.create(uri);
        }

        /**
         * Return a {@link ProtocolBinding} instance parsing a {@link String}.
         */
        public static ProtocolBinding parse(String protocol) {
            final String string = SamlUtilities.toString(protocol);
            if (string == null) return null;
            final URI uri = URI.create(string);
            for (ProtocolBinding binding: ProtocolBinding.values()) {
                if (binding.uri.equals(uri)) return binding;
            }
            throw new IllegalArgumentException("Unknown SAML protocol binding " + string);
        }

        /**
         * Return the <i>SAML</i> constant for this {@link ProtocolBinding}.
         */
        @Override
        public String toString() {
            return uri.toASCIIString();
        }

    }

    /* ====================================================================== */

    /**
     * The supported <i>SAML Name ID Formats</i>
     *
     * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
     */
    public enum NameIdFormat {

        /** Unspecified: <code>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</code> */
        UNSPECIFIED("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"),
        /** Email Address: <code>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</code> */
        EMAIL_ADDRESS("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");

        private final URI uri;

        private NameIdFormat(String uri) {
            this.uri = URI.create(uri);
        }

        /**
         * Return a {@link NameIdFormat} instance parsing a {@link String}.
         */
        public static NameIdFormat parse(String nameIdFormat) {
            final String string = SamlUtilities.toString(nameIdFormat);
            if (string == null) return null;
            final URI uri = URI.create(string);
            for (NameIdFormat format: NameIdFormat.values()) {
                if (format.uri.equals(uri)) return format;
            }
            throw new IllegalArgumentException("Unknown SAML format " + string);
        }

        /**
         * Return the <i>SAML</i> constant for this {@link NameIdFormat}.
         */
        @Override
        public String toString() {
            return uri.toASCIIString();
        }

    }

    /* ====================================================================== */

    /**
     * The supported <i>SAML Authentication Statuses</i>
     *
     * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
     */
    public enum Status {
        /** Success: <code>urn:oasis:names:tc:SAML:2.0:status:Success</code> */
        SUCCESS("urn:oasis:names:tc:SAML:2.0:status:Success"),
        /** Authentication failed: <code>urn:oasis:names:tc:SAML:2.0:status:AuthnFailed</code> */
        AUTHN_FAILED("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"),
        /** Request denied: <code>urn:oasis:names:tc:SAML:2.0:status:RequestDenied</code> */
        REQUEST_DENIED("urn:oasis:names:tc:SAML:2.0:status:RequestDenied"),
        /** <i>SAML</i> version mismatch: <code>urn:oasis:names:tc:SAML:2.0:status:VersionMismatch</code> */
        VERSION_MISMATCH("urn:oasis:names:tc:SAML:2.0:status:VersionMismatch");

        private final URI uri;

        private Status(String uri) {
            this.uri = URI.create(uri);
        }

        /**
         * Return a {@link Status} instance parsing a {@link String}.
         */
        public static Status parse(String status) {
            final String string = SamlUtilities.toString(status);
            if (string == null) return null;
            final URI uri = URI.create(string);
            for (Status value: Status.values()) {
                if (value.uri.equals(uri)) return value;
            }
            throw new IllegalArgumentException("Unknown SAML value " + string);
        }

        /**
         * Return the <i>SAML</i> constant for this {@link Status}.
         */
        @Override
        public String toString() {
            return uri.toASCIIString();
        }

    }

    /* ====================================================================== */

    /**
     * An enumeration indicating what part of a response should be signed.
     *
     * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
     */
    public enum SignatureTarget {

        /** Sign only the <i>SAML Protocol Response</i> element. */
        RESPONSE,
        /** Sign only the <i>SAML Assertion</i> element (this is the default). */
        ASSERTION,
        /** Sign both the <i>SAML Protocol Response</i> and  <i>SAML Assertion</i> elements. */
        BOTH;

    }

    /* ====================================================================== */

    /**
     * A collection of <i>XML namespaces</i> for <i>SAML</i> processing.
     *
     * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
     */
    public enum Namespace {
        /**
         * The <i>SAML Protocol</i> namespace.
         * <dl>
         *   <dt>Prefix</dt><dd><code>samlp</code></dd>
         *   <dt>URI</dt><dd><code>urn:oasis:names:tc:SAML:2.0:protocol</code></dd>
         * </dl>
         */
        SAMLP("samlp", "urn:oasis:names:tc:SAML:2.0:protocol"),
        /**
         * The <i>SAML Assertion</i> namespace.
         * <dl>
         *   <dt>Prefix</dt><dd><code>saml</code></dd>
         *   <dt>URI</dt><dd><code>urn:oasis:names:tc:SAML:2.0:assertion</code></dd>
         * </dl>
         */
        SAML("saml", "urn:oasis:names:tc:SAML:2.0:assertion"),
        /**
         * The <i>XML Digital Signatures</i> namespace.
         * <dl>
         *   <dt>Prefix</dt><dd><code>dsig</code></dd>
         *   <dt>URI</dt><dd><code>http://www.w3.org/2000/09/xmldsig#</code></dd>
         * </dl>
         */
        DSIG("dsig", XMLSignature.XMLNS);

        private static NamespaceContext context;

        /** The <i>prefix</i> of this namespace. */
        public final String PREFIX;
        /** The <i>uri</i> of this namespace. */
        public final String URI;

        private Namespace(String prefix, String uri) {
            PREFIX = prefix;
            URI = uri;
        }

        /**
         * Return a {@link NamespaceContext} containing all known <i>SAML</i>
         * namespaces.
         */
        public static NamespaceContext context() {
            if (context != null) return context;
            return context = new NamespaceContext() {

                private final Map<String, String> prefixes = new HashMap<>();
                private final Map<String, String> namespaces = new HashMap<>();

                {
                    for (Namespace namespace: Namespace.values()) {
                        prefixes.put(namespace.PREFIX, namespace.URI);
                        namespaces.put(namespace.URI, namespace.PREFIX);
                    }
                }

                @Override public String getNamespaceURI(String prefix) { return prefixes.get(prefix); }
                @Override public String getPrefix(String namespaceURI) { return namespaces.get(namespaceURI); }
                @Override public Iterator<?> getPrefixes(String namespaceURI) { return singletonIterator(getPrefix(namespaceURI)); }

            };
        }

    };
}
