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
import java.util.Date;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;

import org.usrz.libs.saml.Saml.NameIdFormat;
import org.usrz.libs.saml.Saml.ProtocolBinding;
import org.w3c.dom.Document;

/**
 * A helper class to build <i>SAML Authorization Request</i> objects.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class SamlAuthnRequestParser {

    public SamlAuthnRequestParser() {
        /* Nothing to do, really */
    }

    /**
     * Parse a <i>SAML Authorization Request</i> into a {@link SamlAuthnRequest}
     * instance.
     *
     * @param request The request, base-64 encoded, possibly deflated.
     * @param inflate Whether the data in the request should be inflated.
     */
    public SamlAuthnRequest parse(String request, boolean inflate) {
        final SamlCodec codec = new SamlCodec(inflate);
        final Document document = SamlUtilities.parse(codec.decode(request));
        final XPath xpath = SamlUtilities.newXPath();

        final String id;
        final String issuer;
        final String version;
        final Date issueInstant;
        final NameIdFormat nameIdPolicy;
        final ProtocolBinding protocolBinding;
        final URI assertionConsumerServiceURL;

        try {
            id = SamlUtilities.toString(xpath.evaluate("samlp:AuthnRequest/@ID", document));
            issuer = SamlUtilities.toString(xpath.evaluate("samlp:AuthnRequest/saml:Issuer", document));
            version = SamlUtilities.toString(xpath.evaluate("samlp:AuthnRequest/@Version", document));
            issueInstant = SamlUtilities.toDate(xpath.evaluate("samlp:AuthnRequest/@IssueInstant", document));
            nameIdPolicy = NameIdFormat.parse(xpath.evaluate("samlp:AuthnRequest/samlp:NameIDPolicy/@Format", document));
            protocolBinding = ProtocolBinding.parse(xpath.evaluate("samlp:AuthnRequest/@ProtocolBinding", document));
            assertionConsumerServiceURL = SamlUtilities.toURI(xpath.evaluate("samlp:AuthnRequest/@AssertionConsumerServiceURL", document));
        } catch (XPathExpressionException exception) {
            throw new IllegalStateException("Exception evaluating XPath", exception);
        }

        return new SamlAuthnRequest() {
            @Override public String getID()                       { return id;  }
            @Override public String getIssuer()                   { return issuer;  }
            @Override public String getVersion()                  { return version; }
            @Override public Date getIssueInstant()               { return issueInstant; }
            @Override public NameIdFormat getNameIDPolicy()       { return nameIdPolicy; }
            @Override public ProtocolBinding getProtocolBinding() { return protocolBinding; }
            @Override public URI getAssertionConsumerServiceURL() { return assertionConsumerServiceURL; }
        };
    }
}
