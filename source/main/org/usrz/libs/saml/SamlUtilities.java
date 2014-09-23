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

import static java.time.temporal.ChronoUnit.SECONDS;
import static org.usrz.libs.utils.Charsets.UTF8;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.Date;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.xml.sax.SAXException;

/**
 * Utility methods for <i>SAML</i> processing.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class SamlUtilities {

    private SamlUtilities() {
        throw new IllegalArgumentException("Do not construct");
    }

    /**
     * Normalize and return a {@link String} from an {@link Object}.
     */
    public static String toString(Object object) {
        if (object == null) return null;

        final String string = object instanceof String  ? ((String) object) :
                              object instanceof Date    ? ((Date) object).toInstant().truncatedTo(SECONDS).toString() :
                              object instanceof Instant ? ((Instant) object).truncatedTo(SECONDS).toString() :
                              object.toString();

        if (string == null) return null; // object.toString() might return null
        final String trimmed = string.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * Normalize and return a {@link Date} from an {@link Object}.
     */
    public static Date toDate(Object object) {
        if (object instanceof Date) return (Date) object;
        if (object instanceof Instant) return Date.from(((Instant) object).truncatedTo(SECONDS));
        final String string = toString(object);
        if (string == null) return null;
        return Date.from(Instant.parse(string).truncatedTo(SECONDS));
    }

    /**
     * Normalize and return an {@link URI} from an {@link Object}.
     */
    public static URI toURI(Object object) {
        if (object instanceof URI) return (URI) object;
        final String string = toString(object);
        if (string == null) return null;
        return URI.create(string);
    }

    /* ====================================================================== */

    /**
     * Return a new {@link DocumentBuilder} for parsing into <i>DOM</i>.
     */
    public static DocumentBuilder newDocumentBuilder() {
        final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setValidating(false);
        documentBuilderFactory.setIgnoringComments(true);
        documentBuilderFactory.setIgnoringElementContentWhitespace(true);
        try {
            return documentBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException exception) {
            throw new IllegalStateException("Unable to create parser", exception);
        }
    }

    /**
     * Parse some XML into a <i>DOM</i>.
     */
    public static Document parse(byte[] data) {
        try {
            return newDocumentBuilder().parse(new ByteArrayInputStream(data));
        } catch (SAXException | IOException exception) {
            throw new IllegalArgumentException("Unable to parse XML data", exception);
        }
    }

    /**
     * Serialize a <i>DOM</i> into its <i>UTF-8 XML</i> representation.
     */
    public static byte[] serialize(Document document) {
        return serialize(document, 0);
    }

    /**
     * Serialize a <i>DOM</i> into its <i>UTF-8 XML</i> representation
     * optionally indenting by 2 characters.
     */
    public static byte[] serialize(Document document, boolean indent) {
        return serialize(document, indent ? 2 : 0);
    }

    /**
     * Serialize a <i>DOM</i> into its <i>UTF-8 XML</i> representation
     * optionally indenting by the specified number of characters.
     */
    public static byte[] serialize(Document document, int indent) {
        try {
            final ByteArrayOutputStream output = new ByteArrayOutputStream();
            final StreamResult result = new StreamResult(output);
            final DOMSource source = new DOMSource(document);
            final Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.ENCODING, UTF8.name());
            if (indent > 0) {
                transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", Integer.toString(indent));
                transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            }
            transformer.transform(source, result);
            return output.toByteArray();
        } catch (TransformerException exception) {
            throw new IllegalStateException("Unable to serialize DOM", exception);
        }

    }

    /**
     * Create a new, empty {@link Document} with the specified root element.
     */
    public static Document newDocument(String namespaceURI, String qualifiedName) {
        try {
            return DOMImplementationRegistry
                .newInstance()
                .getDOMImplementation("XML 3.0")
                .createDocument(namespaceURI, qualifiedName, null);
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException exception) {
            throw new IllegalStateException("DOM Implementation can not be created", exception);
        }
    }

    /**
     * Create a new {@link XPath} instance bound to the various
     * {@linkplain Saml.Namespace <i>SAML</i> namespaces}.
     */
    public static XPath newXPath() {
        final XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setNamespaceContext(Saml.Namespace.context());
        return xpath;
    }

}
