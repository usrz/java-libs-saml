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

import static javax.xml.crypto.dsig.CanonicalizationMethod.INCLUSIVE;
import static javax.xml.crypto.dsig.DigestMethod.SHA1;
import static javax.xml.crypto.dsig.SignatureMethod.RSA_SHA1;
import static javax.xml.crypto.dsig.Transform.ENVELOPED;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.w3c.dom.Element;

public class SamlSigner {

    private final XMLSignatureFactory signatureFactory;
    private final RSAPrivateKey privateKey;
    private final KeyInfo keyInfo;

    /* Create our SamlSigner instance */
    SamlSigner(XMLSignatureFactory signatureFactory, RSAPrivateKey key, X509Certificate certificate) {
        this.signatureFactory = signatureFactory;

        /* Create the KeyInfo containing the X509Data */
        final List<X509Certificate> x509Content = Collections.singletonList(certificate);
        final KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
        final X509Data x509Data = keyInfoFactory.newX509Data(x509Content);
        keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));

        /* Remember our private key */
        privateKey = key;

    }

    public void sign(Element context, Element nextSibling)
    throws MarshalException, XMLSignatureException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        /* Initialize the basics... */
        final CanonicalizationMethod canonicalizationMethod = signatureFactory.newCanonicalizationMethod(INCLUSIVE, (C14NMethodParameterSpec) null);
        final Transform transform = signatureFactory.newTransform(ENVELOPED, (TransformParameterSpec) null);
        final SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(RSA_SHA1, null);
        final DigestMethod digestMethod = signatureFactory.newDigestMethod(SHA1, null);

        /* Create a DOMSignContext, specify the RSA PrivateKey and samlpResponse (root element) */
        final DOMSignContext domSignContext = new DOMSignContext(privateKey, context, nextSibling);

        /* Create the XMLSignature and sign the enveloped signature */
        final Reference reference = signatureFactory.newReference("#" + context.getAttribute("ID"), digestMethod, Collections.singletonList(transform), null, null);
        final SignedInfo signedInfo = signatureFactory.newSignedInfo(canonicalizationMethod, signatureMethod, Collections.singletonList(reference));
        final XMLSignature signature = signatureFactory.newXMLSignature(signedInfo, keyInfo);
        signature.sign(domSignContext);
    }
}
