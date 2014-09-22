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

import static org.usrz.libs.utils.Check.notNull;
import static org.w3c.dom.ls.DOMImplementationLS.MODE_SYNCHRONOUS;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.util.Date;

import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.usrz.libs.saml.Saml.Format;
import org.usrz.libs.saml.Saml.ProtocolBinding;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSParser;

public class SamlFactory {

    private final SamlCodec codec = new SamlCodec();

    private final XMLSignatureFactory signatureFactory;
    private final DOMImplementation domImplementation;
    private final DOMImplementationLS domLoadSave;
    private final XPath xpath;

    public SamlFactory() {
        try {
            final DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            domImplementation = registry.getDOMImplementation("XML 3.0");
            domLoadSave = (DOMImplementationLS) domImplementation.getFeature("LS", "3.0");
        } catch (Exception exception) {
            throw new IllegalStateException("DOM Implementation can not be created", exception);
        }

        xpath = XPathFactory.newInstance().newXPath();
        xpath.setNamespaceContext(Saml.Namespace.context());
        signatureFactory = XMLSignatureFactory.getInstance("DOM");
    }

    public SamlResponseBuilder prepareResponse(SamlAuthnRequest request) {
        return new SamlResponseBuilder(signatureFactory, domImplementation, domLoadSave,
                                       notNull(request, "Null SAML Authn Request"));
    }

    public SamlAuthnRequest parseAuthnRequest(String request) {
        final InputStream stream = new ByteArrayInputStream(codec.decode(request));
        final Document document;
        try {
            final LSInput input = domLoadSave.createLSInput();
            input.setByteStream(stream);
            final LSParser parser = domLoadSave.createLSParser(MODE_SYNCHRONOUS, null);
            document = parser.parse(input);
        } catch (Exception exception) {
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
