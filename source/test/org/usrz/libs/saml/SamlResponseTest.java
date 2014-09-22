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

import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Validator;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.usrz.libs.crypto.pem.PEMProvider;
import org.usrz.libs.testing.AbstractTest;
import org.usrz.libs.testing.IO;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class SamlResponseTest extends AbstractTest {

    private XMLSignatureFactory signatures;
    private SamlFactory factory;
    private SamlAuthnRequest request;
    private Key key;
    private Certificate cert;
    private XPath xpath;

    @BeforeClass
    public void initialize()
    throws Exception {
        final String decoded = "fVLJTsMwEL0j8Q+W79mqHsBqggoIUYklooEDN9eZNAbHEzxOC3w9bgoCDiD5YL0Zv2U8s5PXzrANONJoc57FKWdgFdbarnN+X11ER/ykODyYkexML+aDb+0dvAxAnoWXlsRYyPngrEBJmoSVHZDwSizn11diEqeid+hRoeFscZ7zftWiVqifUDXQSoTaGiub51XdGzCmflKtbUA+c/bwZWuys7UgGmBhyUvrA5Rm0yg9jiZZlU3FNA3nkbPyU+lU232C/2yt9k0kLquqjMrbZTUSbHQN7iZ053yNuDYQK+x28qUk0psAN9IQcDYnAueDwTO0NHTgluA2WsH93VXOW+97Ekmy3W7jb5pEJgO59/1VES/GuYoxmvsx0P+Nyy9hXnxTz5IfVMXnf+1iLM5LNFq9sbkxuD1zIH3I4N0QIlyg66T/Wy2LsxHRddSMrWKw1IPSjYaas6TYq/5ejLAuHw==";
        factory = new SamlFactory();
        request = factory.parseAuthnRequest(decoded);

        Security.addProvider(new PEMProvider());
        final KeyStore keyStore = KeyStore.getInstance("PEM");
        keyStore.load(IO.resource("selfsigned.pem"), "asdf".toCharArray());

        key = keyStore.getKey("F7A4FD46266A272B145B4F09F6D14CC7A458268B", "asdf".toCharArray());
        cert = keyStore.getCertificate("F7A4FD46266A272B145B4F09F6D14CC7A458268B");

        xpath = XPathFactory.newInstance().newXPath();
        xpath.setNamespaceContext(Saml.Namespace.context());

        signatures = XMLSignatureFactory.getInstance("DOM");
    }

    @Test
    public void testResponse()
    throws Exception {
        final SamlResponseBuilder builder = factory.prepareResponse(request)
                .withIssuer("http://www.usrz.com/saml/something")
                .withSubject("foo@bar.com");

        final Validator validator = SchemaResolver.validator(SchemaResolver.SAML_PROTOCOL);
        validator.validate(new DOMSource(builder.buildDocument()));
    }

    @Test
    public void testResponseSigned()
    throws Exception {
        final SamlResponseBuilder builder = factory.prepareResponse(request)
                .withIssuer("http://www.usrz.com/saml/something")
                .withSubject("foo@bar.com")
                .withSignature(key, cert);

        final Validator validator = SchemaResolver.validator(SchemaResolver.SAML_PROTOCOL);
        final Document document = builder.buildDocument();
        validator.validate(new DOMSource(document));

        final String response = xpath.evaluate("/samlp:Response/ds:Signature/ds:SignatureValue", document);
        final String assertion = xpath.evaluate("/samlp:Response/saml:Assertion/ds:Signature/ds:SignatureValue", document);
        assertNotNull(response, "Null response signature");
        assertNotNull(assertion, "Null assertion signature");
        assertNotEquals(response, "", "Null response signature");
        assertNotEquals(assertion, "", "Null assertion signature");
        assertNotEquals(response.replaceAll("\\s+", ""), assertion.replaceAll("\\s+", ""));

        assertTrue(validateSignatures(document), "One (or more) of the signatures is not valid");
    }

    @Test
    public void testResponseSignedResponseOnly()
    throws Exception {
        final SamlResponseBuilder builder = factory.prepareResponse(request)
                .withIssuer("http://www.usrz.com/saml/something")
                .withSubject("foo@bar.com")
                .withSignature(key, cert, true, false);

        final Validator validator = SchemaResolver.validator(SchemaResolver.SAML_PROTOCOL);
        final Document document = builder.buildDocument();
        validator.validate(new DOMSource(document));

        assertNotNull(xpath.evaluate("/samlp:Response/ds:Signature/ds:SignatureValue", document), "Null response signature");
        assertNotEquals(xpath.evaluate("/samlp:Response/ds:Signature/ds:SignatureValue", document), "", "Empty response signature");
        assertEquals(xpath.evaluate("/samlp:Response/saml:Assertion/ds:Signature/ds:SignatureValue", document), "", "Non-empty assertion signature");

        assertTrue(validateSignatures(document), "One (or more) of the signatures is not valid");
    }

    @Test
    public void testResponseSignedAssertionOnly()
    throws Exception {
        final SamlResponseBuilder builder = factory.prepareResponse(request)
                .withIssuer("http://www.usrz.com/saml/something")
                .withSubject("foo@bar.com")
                .withSignature(key, cert, false, true);

        final Validator validator = SchemaResolver.validator(SchemaResolver.SAML_PROTOCOL);
        final Document document = builder.buildDocument();
        validator.validate(new DOMSource(document));

        assertEquals(xpath.evaluate("/samlp:Response/ds:Signature/ds:SignatureValue", document), "", "Non-empty response signature");
        assertNotNull(xpath.evaluate("/samlp:Response/saml:Assertion/ds:Signature/ds:SignatureValue", document), "Null assertion signature");
        assertNotEquals(xpath.evaluate("/samlp:Response/saml:Assertion/ds:Signature/ds:SignatureValue", document), "", "Empty assertion signature");

        assertTrue(validateSignatures(document), "One (or more) of the signatures is not valid");
    }

    /* ====================================================================== */

    public boolean validateSignatures(Document document) throws Exception {
        final NodeList nodeList = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nodeList.getLength() == 0) throw new Exception("No signatures in document");

        boolean overallValidity = true;
        for (int x = 0; x < nodeList.getLength(); x ++) {
            final DOMValidateContext validateContext = new DOMValidateContext(cert.getPublicKey(), nodeList.item(x));
            final XMLSignature signature = signatures.unmarshalXMLSignature(validateContext);
            boolean coreValidity = signature.validate(validateContext);

            overallValidity &= coreValidity;
            if (coreValidity == false) {
                System.err.println("Signature failed core validation");
                boolean signatureValidity = signature.getSignatureValue().validate(validateContext);
                System.err.println(" -> Signature validity: " + signatureValidity);

                for (Object object: signature.getSignedInfo().getReferences()) {
                    final Reference reference = (Reference) object;
                    final boolean referenceValidity = reference.validate(validateContext);
                    System.err.println(" -> Reference[" + reference + "] validity: " + referenceValidity);
                }
            }
        }

        return overallValidity;
    }
}
