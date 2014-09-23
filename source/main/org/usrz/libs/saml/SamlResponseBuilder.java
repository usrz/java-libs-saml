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
import static org.usrz.libs.saml.Saml.SignatureTarget.ASSERTION;
import static org.usrz.libs.utils.Charsets.UTF8;
import static org.usrz.libs.utils.Check.notNull;

import java.net.URI;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;

import org.usrz.libs.saml.Saml.NameIdFormat;
import org.usrz.libs.saml.Saml.SignatureTarget;
import org.usrz.libs.saml.Saml.Status;
import org.usrz.libs.utils.Check;
import org.usrz.libs.utils.Strings;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * A <i>builder</i> for a <i>SAML Response</i>.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class SamlResponseBuilder {

    /* With sensible defaults */
    private String responseId = SAMLP.PREFIX + "-" + Strings.random(32);
    private String assertionId = SAML.PREFIX + "-" + Strings.random(32);
    private String sessionId = "session-" + Strings.random(32);

    private Instant issueInstant = Instant.now();
    private Instant notBefore = issueInstant.minusSeconds(300);
    private Instant notOnOrAfter = issueInstant.plusSeconds(300);

    private Status statusCodeValue = Status.SUCCESS;
    private NameIdFormat subjectFormat = NameIdFormat.EMAIL_ADDRESS;

    /* MUST be specified */
    private String inResponseTo = null;
    private String subject = null;
    private String issuer = null;

    /* Optional values */
    private String destination = null;
    private String recipient = null;
    private String audience = null;

    /* Signature, optionally null */
    private RSAPrivateKey privateKey;
    private X509Certificate certificate;
    private boolean signResponse;
    private boolean signAssertion;

    /**
     * Create a new {@link SamlResponseBuilder} instance.
     */
    public SamlResponseBuilder() {
        /* Nothing to do */
    }

    /**
     * Build a <i>DOM</i> {@link Document}.
     */
    public Document buildDocument() {
        if (inResponseTo == null) throw new IllegalStateException("Missing in response to field");
        if (subject == null) throw new IllegalStateException("Missing subject field");
        if (issuer == null) throw new IllegalStateException("Missing issuer field");

        final Document document = SamlUtilities.newDocument(SAMLP.URI, "samlp:Response");
        final Element samlpResponse = document.getDocumentElement();
        samlpResponse.setAttributeNS(XMLNS_ATTRIBUTE_NS_URI, "xmlns:samlp", SAMLP.URI);
        samlpResponse.setAttributeNS(XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml",  SAML.URI);

        /* Attributes for the root element */
        samlpResponse.setAttribute("ID", responseId);
        samlpResponse.setIdAttribute("ID", true);
        samlpResponse.setAttribute("Version", Saml.VERSION);
        samlpResponse.setAttribute("InResponseTo", inResponseTo);
        samlpResponse.setAttribute("IssueInstant", SamlUtilities.toString(issueInstant));

        /* Destination attribute only if set */
        if (destination != null) samlpResponse.setAttribute("Destination", destination);

        /* Issuer */
        final Element samlIssuer = document.createElementNS(SAML.URI, "saml:Issuer");
        samlpResponse.appendChild(samlIssuer);

        samlIssuer.appendChild(document.createTextNode(issuer));

        /* Status and Status Code */
        final Element samlpStatus = document.createElementNS(SAMLP.URI, "samlp:Status");
        samlpResponse.appendChild(samlpStatus);

        final Element samlpStatusCode = document.createElementNS(SAMLP.URI, "samlp:StatusCode");
        samlpStatus.appendChild(samlpStatusCode);

        samlpStatusCode.setAttribute("Value", SamlUtilities.toString(statusCodeValue));

        /* Assertion */
        final Element samlAssertion = document.createElementNS(SAML.URI, "saml:Assertion");
        samlpResponse.appendChild(samlAssertion);

        samlAssertion.setAttribute("ID", assertionId);
        samlAssertion.setIdAttribute("ID", true);

        samlAssertion.setAttribute("Version", Saml.VERSION);
        samlAssertion.setAttribute("IssueInstant", SamlUtilities.toString(issueInstant));


        /* Clone Response issuer -> Assertion issuer */
        samlAssertion.appendChild(document.adoptNode(samlIssuer.cloneNode(true)));


        /* Subject format and value */
        final Element samlSubject = document.createElementNS(SAML.URI, "saml:Subject");
        samlAssertion.appendChild(samlSubject);

        final Element samlNameId = document.createElementNS(SAML.URI, "saml:NameID");
        samlSubject.appendChild(samlNameId);

        samlNameId.setAttribute("Format", SamlUtilities.toString(subjectFormat));
        samlNameId.appendChild(document.createTextNode(subject));


        /* Subject confirmation and its data */
        final Element samlSubjectConfirmation = document.createElementNS(SAML.URI, "saml:SubjectConfirmation");
        samlSubject.appendChild(samlSubjectConfirmation);

        samlSubjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer");

        final Element samlSubjectConfirmationData = document.createElementNS(SAML.URI, "saml:SubjectConfirmationData");
        samlSubjectConfirmation.appendChild(samlSubjectConfirmationData);

        samlSubjectConfirmationData.setAttribute("NotBefore", SamlUtilities.toString(notBefore));
        samlSubjectConfirmationData.setAttribute("NotOnOrAfter", SamlUtilities.toString(notOnOrAfter));
        samlSubjectConfirmationData.setAttribute("InResponseTo", inResponseTo);

        if (recipient != null) samlSubjectConfirmationData.setAttribute("Recipient", recipient);

        /* Conditions */
        final Element samlConditions = document.createElementNS(SAML.URI, "saml:Conditions");
        samlAssertion.appendChild(samlConditions);

        samlConditions.setAttribute("NotBefore", SamlUtilities.toString(notBefore));
        samlConditions.setAttribute("NotOnOrAfter", SamlUtilities.toString(notOnOrAfter));

        final Element samlAudienceRestriction = document.createElementNS(SAML.URI, "saml:AudienceRestriction");
        samlConditions.appendChild(samlAudienceRestriction);

        /* Optional audience restriction */
        if (audience != null) {
            final Element samlAudience = document.createElementNS(SAML.URI, "saml:Audience");
            samlAudienceRestriction.appendChild(samlAudience);
            samlAudience.appendChild(document.createTextNode(audience));
        }

        /* Authentication statement and its context */
        final Element samlAuthnStatement = document.createElementNS(SAML.URI, "saml:AuthnStatement");
        samlAssertion.appendChild(samlAuthnStatement);

        samlAuthnStatement.setAttribute("AuthnInstant", SamlUtilities.toString(issueInstant));
        samlAuthnStatement.setAttribute("SessionIndex", sessionId);

        final Element samlAuthnContext = document.createElementNS(SAML.URI, "saml:AuthnContext");
        samlAuthnStatement.appendChild(samlAuthnContext);

        final Element samlAuthnContextClassRef = document.createElementNS(SAML.URI, "saml:AuthnContextClassRef");
        samlAuthnContext.appendChild(samlAuthnContextClassRef);

        /* Fudge it, keep this as a constant */
        samlAuthnContextClassRef.appendChild(document.createTextNode("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"));


        /* Normalize the document before signing */
        document.normalizeDocument();


        /* Signature! */
        if ((privateKey != null) && (certificate != null)) try {
            final SamlSigner signer = new SamlSigner(privateKey, certificate);

            /* First sign the assertion (contained in response, sooo) */
            if (signAssertion) signer.sign(samlAssertion, samlSubject);

            /* After the assertion, sign the outside response wrapper */
            if (signResponse) signer.sign(samlpResponse, samlpStatus);

        } catch (Exception exception) {
            throw new IllegalStateException("Unable to sign SAML response", exception);
        }

        return document;
    }

    /**
     * Build a {@link String} containing the <i>XML</i> document.
     */
    public String buildXML() {
        return new String(buildBytes(), UTF8);
    }

    /**
     * Build an encoded {@link String} (base-64 format) suitable for including
     * in an HTTP response, optionally compressing it.
     */
    public String build(boolean compress) {
        return new SamlCodec(compress).encode(buildBytes());
    }

    /* ---------------------------------------------------------------------- */

    private byte[] buildBytes() {
        return SamlUtilities.serialize(buildDocument(), false);
    }

    /* ====================================================================== */

    /**
     * Specify the <i>response id</i> (default: automatically generated).
     */
    public SamlResponseBuilder withResponseId(String responseId) {
        this.responseId = Check.notNull(SamlUtilities.toString(responseId), "Null response id");
        return this;
    }

    /**
     * Specify the <i>assertion id</i> (default: automatically generated).
     */
    public SamlResponseBuilder withAssertionId(String assertionId) {
        this.assertionId = Check.notNull(SamlUtilities.toString(assertionId), "Null assertion id");
        return this;
    }

    /**
     * Specify the <i>session id</i> (default: automatically generated).
     */
    public SamlResponseBuilder withSessionId(String sessionId) {
        this.sessionId = Check.notNull(SamlUtilities.toString(assertionId), "Null session id");
        return this;
    }

    /**
     * Specify the <i>in response to</i> field for this response (no default, <b>required</b>).
     */
    public SamlResponseBuilder withInResponseTo(String inResponseTo) {
        this.inResponseTo = Check.notNull(SamlUtilities.toString(inResponseTo), "Null in-response-to id");
        return this;
    }

    /**
     * Specify the <i>issuer</i> of this response (no default, <b>required</b>).
     */
    public SamlResponseBuilder withIssuer(String issuer) {
        this.issuer = Check.notNull(SamlUtilities.toString(issuer), "Null issuer");
        return this;
    }

    /**
     * Specify the <i>issue instant</i> (default: now).
     */
    public SamlResponseBuilder withIssueInstant(Date issueInstant) {
        this.issueInstant = Check.notNull(issueInstant, "Null date").toInstant();
        return this;
    }

    /**
     * Specify the <i>not before</i> constraint (default: 5 minutes before now).
     */
    public SamlResponseBuilder withNotBefore(Date notBefore) {
        this.notBefore = Check.notNull(notBefore, "Null date").toInstant();
        return this;
    }

    /**
     * Specify the <i>not on or after</i> constraint (default: 5 minutes after now).
     */
    public SamlResponseBuilder withNotOnOrAfter(Date notOnOrAfter) {
        this.notOnOrAfter = Check.notNull(notOnOrAfter, "Null date").toInstant();
        return this;
    }

    /**
     * Specify the <i>status</i> of this response (default: {@link Status#SUCCESS}).
     */
    public SamlResponseBuilder withStatusCodeValue(Status statusCodeValue) {
        this.statusCodeValue = Check.notNull(statusCodeValue, "Null status");
        return this;
    }

    /**
     * Specify the <i>name id format</i> of this response (default: {@link NameIdFormat#EMAIL_ADDRESS}).
     */
    public SamlResponseBuilder withSubjectFormat(NameIdFormat subjectFormat) {
        this.subjectFormat = Check.notNull(subjectFormat, "Null format");
        return this;
    }

    /**
     * Specify the <i>subject</i> of this response (no default, <b>required</b>).
     */
    public SamlResponseBuilder withSubject(String subject) {
        this.subject = Check.notNull(SamlUtilities.toString(subject), "Null subject");
        return this;
    }

    /* Optionals ... */

    /**
     * Specify the <i>destination</i> of this response (no default, omitted).
     */
    public SamlResponseBuilder withDestination(URI destination) {
        return this.withDestination(SamlUtilities.toString(destination));
    }

    /**
     * Specify the <i>destination</i> of this response (no default, omitted).
     */
    public SamlResponseBuilder withDestination(String destination) {
        this.destination = SamlUtilities.toString(destination);
        return this;
    }

    /**
     * Specify the <i>audience</i> of this response (no default, omitted).
     */
    public SamlResponseBuilder withAudience(URI audience) {
        return this.withAudience(SamlUtilities.toString(audience));
    }

    /**
     * Specify the <i>audience</i> of this response (no default, omitted).
     */
    public SamlResponseBuilder withAudience(String audience) {
        this.audience = SamlUtilities.toString(audience);
        return this;
    }

    /**
     * Specify the <i>recipient</i> of this response (no default, omitted).
     */
    public SamlResponseBuilder withRecipient(URI recipient) {
        return this.withRecipient(SamlUtilities.toString(recipient));
    }

    /**
     * Specify the <i>recipient</i> of this response (no default, omitted).
     */
    public SamlResponseBuilder withRecipient(String recipient) {
        this.recipient = SamlUtilities.toString(recipient);
        return this;
    }

    /* Signatures */

    /**
     * Specify that the <i>assertion</i> part of this response should be signed
     * with the given {@link Key} and {@link Certificate}.
     */
    public SamlResponseBuilder withSignature(Key privateKey, Certificate certificate) {
        return this.withSignature(privateKey, certificate, ASSERTION);
    }

    /**
     * Specify that the part indicated by the {@link SignatureTarget} of this
     * response should be signed with the given {@link Key} and
     * {@link Certificate}.
     */
    public SamlResponseBuilder withSignature(Key privateKey, Certificate certificate, SignatureTarget signature) {
        if (signature == null) {
            return this.withSignature(privateKey, certificate, false, false);
        } else switch (signature) {
            case RESPONSE:  return this.withSignature(privateKey, certificate, false, false);
            case ASSERTION: return this.withSignature(privateKey, certificate, false, true);
            case BOTH:      return this.withSignature(privateKey, certificate, true, true);
            default:        throw new IllegalArgumentException("Unknown target: "+ signature);
        }
    }

    /**
     * Specify that either the <i>request</i> and/or the  <i>assertion</i> part
     * of this response should be signed with the given {@link Key} and
     * {@link Certificate}.
     */
    public SamlResponseBuilder withSignature(Key privateKey, Certificate certificate, boolean signResponse, boolean signAssertion) {
        if ((signResponse == false) && (signAssertion == false)) {
            this.privateKey = null;
            this.certificate = null;
            this.signResponse = false;
            this.signAssertion = false;
            return this;
        }

        try {
            this.privateKey = (RSAPrivateKey) notNull(privateKey, "Null private key");
            final RSAPublicKey rsaPublic = (RSAPublicKey) certificate.getPublicKey();
            if (!this.privateKey.getModulus().equals(rsaPublic.getModulus())) {
                throw new IllegalArgumentException("Private/public key mismatch");
            }
        } catch (ClassCastException exception) {
            this.privateKey = null;
            throw new IllegalArgumentException("Only RSA keys are supported", exception);
        }

        try {
            this.certificate = (X509Certificate) notNull(certificate, "Null X509 certificate");
        } catch (ClassCastException exception) {
            this.certificate = null;
            throw new IllegalArgumentException("Only X509 certificates are supported", exception);
        }

        this.signResponse = signResponse;
        this.signAssertion = signAssertion;

        return this;
    }

}
