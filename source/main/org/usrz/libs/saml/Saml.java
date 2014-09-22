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

import java.net.URI;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.xml.namespace.NamespaceContext;

public final class Saml {

    private Saml() {
        throw new IllegalStateException("Do not construct");
    }

    /* ====================================================================== */

    public static String toString(Object object) {
        if (object == null) return null;
        final String string = object instanceof String ? (String) object : object.toString();
        if (string == null) return null; // object.toString() might return null
        final String trimmed = string.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    public static Date toDate(Object object) {
        if (object instanceof Date) return (Date) object;
        if (object instanceof Instant) return Date.from((Instant) object);
        final String string = toString(object);
        if (string == null) return null;
        return Date.from(Instant.parse(string));
    }

    public static URI toURI(Object object) {
        if (object instanceof URI) return (URI) object;
        final String string = toString(object);
        if (string == null) return null;
        return URI.create(string);
    }

    /* ====================================================================== */

    public enum ProtocolBinding {
        HTTP_REDIRECT("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),
        HTTP_POST("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

        private final URI uri;

        private ProtocolBinding(String uri) {
            this.uri = URI.create(uri);
        }

        public static ProtocolBinding parse(Object object) {
            final String string = Saml.toString(object);
            if (string == null) return null;
            final URI uri = URI.create(string);
            for (ProtocolBinding binding: ProtocolBinding.values()) {
                if (binding.uri.equals(uri)) return binding;
            }
            throw new IllegalArgumentException("Unknown SAML protocol binding " + string);
        }

        @Override
        public String toString() {
            return uri.toASCIIString();
        }

    }

    /* ====================================================================== */

    public enum Format {
        UNSPECIFIED("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"),
        EMAIL_ADDRESS("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");

        private final URI uri;

        private Format(String uri) {
            this.uri = URI.create(uri);
        }

        public static Format parse(Object object) {
            final String string = Saml.toString(object);
            if (string == null) return null;
            final URI uri = URI.create(string);
            for (Format format: Format.values()) {
                if (format.uri.equals(uri)) return format;
            }
            throw new IllegalArgumentException("Unknown SAML format " + string);
        }

        @Override
        public String toString() {
            return uri.toASCIIString();
        }

    }

    /* ====================================================================== */

    public static final NamespaceContext Namespace = new SamlNamespaceContext();

    private static final class SamlNamespaceContext implements NamespaceContext {
        private final Map<String, String> prefixes;
        private final Map<String, String> namespaces;

        private SamlNamespaceContext() {
            prefixes = new HashMap<>();
            prefixes.put("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            prefixes.put("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

            namespaces = new HashMap<>();
            prefixes.forEach((prefix, namespace) -> namespaces.put(namespace, prefix));
        }

        @Override
        public String getNamespaceURI(String prefix) {
            return prefixes.get(prefix);
        }

        @Override
        public String getPrefix(String namespaceURI) {
            return namespaces.get(namespaceURI);
        }

        @Override
        public Iterator<?> getPrefixes(String namespaceURI) {
            return Collections.singleton(namespaces.get(namespaceURI)).iterator();
        }
    }


}
