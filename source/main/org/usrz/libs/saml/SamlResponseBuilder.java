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

import static javax.xml.XMLConstants.XMLNS_ATTRIBUTE_NS_URI;
import static org.usrz.libs.saml.Saml.Namespace.SAML;
import static org.usrz.libs.saml.Saml.Namespace.SAMLP;
import static org.usrz.libs.utils.Charsets.UTF8;
import static org.usrz.libs.utils.Check.notNull;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;

import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.usrz.libs.saml.Saml.Format;
import org.usrz.libs.saml.Saml.Value;
import org.usrz.libs.utils.Check;
import org.usrz.libs.utils.Strings;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;

public class SamlResponseBuilder {

    private final DOMImplementationLS domLoadSave;
    private final DOMImplementation domImplementation;
    private final XMLSignatureFactory signatureFactory;

    private RSAPrivateKey privateKey;
    private X509Certificate certificate;
    private boolean signResponse;
    private boolean signAssertion;

    private String responseId = "_" + Strings.random(32);
    private String assertionId = "_" + Strings.random(32);
    private String inResponseTo = null;

    private Instant issueInstant = Instant.now();
    private Instant notBefore = issueInstant.minusSeconds(300);
    private Instant notOnOrAfter = issueInstant.plusSeconds(300);

    private URI destination;
    private String issuer;
    private String audience;

    private Value statusCodeValue = Value.SUCCESS;
    private Format subjectFormat = Format.EMAIL_ADDRESS;
    private String subject;

    SamlResponseBuilder(XMLSignatureFactory signatureFactory,
                        DOMImplementation domImplementation,
                        DOMImplementationLS domLoadSave,
                        SamlAuthnRequest request) {
        this.signatureFactory = signatureFactory;
        this.domImplementation = domImplementation;
        this.domLoadSave = domLoadSave;

        withInResponseTo(request.getID());
        withAudience(request.getIssuer());
        withDestination(request.getAssertionConsumerServiceURL());
    }

    public Document buildDocument() {
        final Document document = domImplementation.createDocument(SAMLP.uri(), "samlp:Response", null);
        final Element samlpResponse = document.getDocumentElement();
        samlpResponse.setAttributeNS(XMLNS_ATTRIBUTE_NS_URI, "xmlns:samlp", SAMLP.uri());
        samlpResponse.setAttributeNS(XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml",  SAML.uri());

        /* Attributes for the root element */
        samlpResponse.setAttribute("ID", responseId);
        samlpResponse.setIdAttribute("ID", true);
        samlpResponse.setAttribute("Version", Saml.VERSION);
        samlpResponse.setAttribute("InResponseTo", inResponseTo);
        samlpResponse.setAttribute("IssueInstant", Saml.toString(issueInstant));
        samlpResponse.setAttribute("Destination", Saml.toString(destination));

        /* Issuer */
        if (issuer == null) throw new IllegalStateException("Null issuer");
        final Element samlIssuer = document.createElementNS(SAML.uri(), "saml:Issuer");
        samlpResponse.appendChild(samlIssuer);

        samlIssuer.appendChild(document.createTextNode(issuer));

        /* Status and Status Code */
        final Element samlpStatus = document.createElementNS(SAMLP.uri(), "samlp:Status");
        samlpResponse.appendChild(samlpStatus);

        final Element samlpStatusCode = document.createElementNS(SAMLP.uri(), "samlp:StatusCode");
        samlpStatus.appendChild(samlpStatusCode);

        samlpStatusCode.setAttribute("Value", Saml.toString(statusCodeValue));

        /* Assertion */
        final Element samlAssertion = document.createElementNS(SAML.uri(), "saml:Assertion");
        samlpResponse.appendChild(samlAssertion);

        samlAssertion.setAttribute("ID", assertionId);
        samlAssertion.setIdAttribute("ID", true);

        samlAssertion.setAttribute("Version", Saml.VERSION);
        samlAssertion.setAttribute("IssueInstant", Saml.toString(issueInstant));

        /* Clone Response issuer -> Assertion issuer */
        samlAssertion.appendChild(document.adoptNode(samlIssuer.cloneNode(true)));

        /* Subject format and value */
        if (subject == null) throw new IllegalStateException("Null subject");

        final Element samlSubject = document.createElementNS(SAML.uri(), "saml:Subject");
        samlAssertion.appendChild(samlSubject);

        final Element samlNameId = document.createElementNS(SAML.uri(), "saml:NameID");
        samlSubject.appendChild(samlNameId);

        samlNameId.setAttribute("Format", Saml.toString(subjectFormat));
        samlNameId.appendChild(document.createTextNode(subject));

        /* Conditions */
        final Element samlConditions = document.createElementNS(SAML.uri(), "saml:Conditions");
        samlAssertion.appendChild(samlConditions);

        samlConditions.setAttribute("NotBefore", Saml.toString(notBefore));
        samlConditions.setAttribute("NotOnOrAfter", Saml.toString(notOnOrAfter));

        /* Audience restriction */
        final Element samlAudienceRestriction = document.createElementNS(SAML.uri(), "saml:AudienceRestriction");
        samlConditions.appendChild(samlAudienceRestriction);

        final Element samlAudience = document.createElementNS(SAML.uri(), "saml:Audience");
        samlAudienceRestriction.appendChild(samlAudience);

        samlAudience.appendChild(document.createTextNode(audience));

        document.normalizeDocument();

        /* Signature! */
        if ((privateKey != null) && (certificate != null)) try {
            final SamlSigner signer = new SamlSigner(signatureFactory, privateKey, certificate);

            /* First sign the assertion (contained in response, sooo) */
            if (signAssertion) signer.sign(samlAssertion, samlSubject);

            /* After the assertion, sign the outside response wrapper */
            if (signResponse) signer.sign(samlpResponse, samlpStatus);

        } catch (Exception exception) {
            throw new IllegalStateException("Unable to sign SAML response", exception);
        }

        return document;
    }

    /* ====================================================================== */

    public String buildXML() {
        return new String(buildBytes(), UTF8);
    }

    /* ====================================================================== */

    private byte[] buildBytes() {
        final Document document = buildDocument();
        final ByteArrayOutputStream stream = new ByteArrayOutputStream();
        final LSOutput output = domLoadSave.createLSOutput();
        output.setByteStream(stream);
        output.setEncoding(UTF8.name());
        domLoadSave.createLSSerializer().write(document, output);
        return stream.toByteArray();
    }

    /* ====================================================================== */

    public SamlResponseBuilder withResponseId(String responseId) {
        this.responseId = Check.notNull(Saml.toString(responseId), "Null response id");
        return this;
    }

    public SamlResponseBuilder withAssertionId(String assertionId) {
        this.assertionId = Check.notNull(Saml.toString(assertionId), "Null assertion id");
        return this;
    }

    public SamlResponseBuilder withInResponseTo(String inResponseTo) {
        this.inResponseTo = Check.notNull(Saml.toString(inResponseTo), "Null in-response-to id");
        return this;
    }

    public SamlResponseBuilder withIssueInstant(Date issueInstant) {
        this.issueInstant = Check.notNull(issueInstant, "Null date").toInstant();
        return this;
    }

    public SamlResponseBuilder withNotBefore(Date notBefore) {
        this.notBefore = Check.notNull(notBefore, "Null date").toInstant();
        return this;
    }

    public SamlResponseBuilder withNotOnOrAfter(Date notOnOrAfter) {
        this.notOnOrAfter = Check.notNull(notOnOrAfter, "Null date").toInstant();
        return this;
    }

    public SamlResponseBuilder withDestination(URI destination) {
        this.destination = Check.notNull(destination, "Null destination");
        return this;
    }

    public SamlResponseBuilder withIssuer(String issuer) {
        this.issuer = Check.notNull(Saml.toString(issuer), "Null issuer");
        return this;
    }

    public SamlResponseBuilder withStatusCodeValue(Value statusCodeValue) {
        this.statusCodeValue = Check.notNull(statusCodeValue, "Null status");
        return this;
    }

    public SamlResponseBuilder withSubjectFormat(Format subjectFormat) {
        this.subjectFormat = Check.notNull(subjectFormat, "Null format");
        return this;
    }

    public SamlResponseBuilder withSubject(String subject) {
        this.subject = Check.notNull(Saml.toString(subject), "Null subject");
        return this;
    }

    public SamlResponseBuilder withAudience(String audience) {
        this.audience = Check.notNull(Saml.toString(audience), "Null audience");
        return this;
    }

    public SamlResponseBuilder withSignature(Key privateKey, Certificate certificate) {
        return this.withSignature(privateKey, certificate, true, true);
    }

    public SamlResponseBuilder withSignature(Key privateKey, Certificate certificate, boolean signResponse, boolean signAssertion) {
        if ((signResponse == false) && (signAssertion == false)) return this;
        this.signResponse = signResponse;
        this.signAssertion = signAssertion;

        try {
            this.privateKey = (RSAPrivateKey) notNull(privateKey, "Null private key");
            final RSAPublicKey rsaPublic = (RSAPublicKey) certificate.getPublicKey();
            if (!this.privateKey.getModulus().equals(rsaPublic.getModulus())) {
                throw new IllegalArgumentException("Private/public key mismatch");
            }
        } catch (ClassCastException exception) {
            throw new IllegalArgumentException("Only RSA keys are supported", exception);
        }


        try {
            this.certificate = (X509Certificate) notNull(certificate, "Null X509 certificate");
        } catch (ClassCastException exception) {
            throw new IllegalArgumentException("Only X509 certificates are supported", exception);
        }

        return this;
    }

}
