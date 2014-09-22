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

import static org.usrz.libs.utils.codecs.Base64Codec.BASE_64;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Date;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.usrz.libs.saml.Saml.Format;
import org.usrz.libs.saml.Saml.ProtocolBinding;
import org.usrz.libs.utils.Check;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class SamlFactory {

    private final DocumentBuilderFactory documentBuilder;
    private final XPath xpath;

    public SamlFactory() {
        documentBuilder = DocumentBuilderFactory.newInstance();
        documentBuilder.setNamespaceAware(true);
        xpath = XPathFactory.newInstance().newXPath();
        xpath.setNamespaceContext(Saml.Namespace);
    }

    public SamlAuthnRequest getAuthnRequest(String request) {
        final byte[] decoded = BASE_64.decode(Check.notNull(request, "Null request"));
        final byte[] buffer = new byte[65536];

        final Inflater inflater = new Inflater(true);
        inflater.setInput(decoded);
        final int length;
        try {
            length = inflater.inflate(buffer);
        } catch (DataFormatException exception) {
            throw new IllegalArgumentException("Unable to inflate request", exception);
        }

        final InputStream input = new ByteArrayInputStream(buffer, 0, length);
        final Document document;
        try {
            document = documentBuilder.newDocumentBuilder().parse(input);
        } catch (SAXException | IOException | ParserConfigurationException exception) {
            throw new IllegalArgumentException("Unable to parse request", exception);
        }

        final String id;
        final String issuer;
        final String version;
        final Date issueInstant;
        final String providerName;
        final Format nameIdPolicy;
        final ProtocolBinding protocolBinding;
        final URI assertionConsumerServiceURL;
        try {
            id = Saml.toString(xpath.evaluate("samlp:AuthnRequest/@ID", document));
            issuer = Saml.toString(xpath.evaluate("samlp:AuthnRequest/saml:Issuer", document));
            version = Saml.toString(xpath.evaluate("samlp:AuthnRequest/@Version", document));
            issueInstant = Saml.toDate(xpath.evaluate("samlp:AuthnRequest/@IssueInstant", document));
            providerName = Saml.toString(xpath.evaluate("samlp:AuthnRequest/@ProviderName", document));
            nameIdPolicy = Format.parse(xpath.evaluate("samlp:AuthnRequest/samlp:NameIDPolicy/@Format", document));
            protocolBinding = ProtocolBinding.parse(xpath.evaluate("samlp:AuthnRequest/@ProtocolBinding", document));
            assertionConsumerServiceURL = Saml.toURI(xpath.evaluate("samlp:AuthnRequest/@AssertionConsumerServiceURL", document));
        } catch (XPathExpressionException exception) {
            throw new IllegalStateException("Exception evaluating XPath", exception);
        }

        return new SamlAuthnRequest() {
            @Override public String getID()                       { return id;  }
            @Override public String getIssuer()                   { return issuer;  }
            @Override public String getVersion()                  { return version; }
            @Override public Date getIssueInstant()               { return issueInstant; }
            @Override public String getProviderName()             { return providerName; }
            @Override public Format getNameIDPolicy()             { return nameIdPolicy; }
            @Override public ProtocolBinding getProtocolBinding() { return protocolBinding; }
            @Override public URI getAssertionConsumerServiceURL() { return assertionConsumerServiceURL; }
        };
    }
}
