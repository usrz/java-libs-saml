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

import static javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI;

import java.io.File;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;

import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;

public class SchemaResolver implements LSResourceResolver {

    public static final String SAML_ASSERTIONS = "http://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd";
    public static final String SAML_PROTOCOL = "http://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd";

    private final DOMImplementationLS domLoadSave;

    private SchemaResolver() throws Exception {
        final DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
        domLoadSave = (DOMImplementationLS) registry.getDOMImplementation("XML 3.0")
                                                    .getFeature("LS", "3.0");
    }

    @Override
    @SuppressWarnings("resource")
    public LSInput resolveResource(String type, String namespaceURI, String publicId, String systemId, String baseURI) {
        final URI uri = URI.create(systemId == null ? baseURI : systemId);

        final String resource = "schemas/" + new File(uri.getPath()).getName();
        final InputStream stream = this.getClass().getResourceAsStream(resource);
        if (stream == null) throw new IllegalArgumentException("Schema \"" + systemId + "\" at \"" + baseURI + "\" not found");

        final LSInput input = domLoadSave.createLSInput();
        input.setByteStream(stream);
        return input;
    }

    public static final Validator validator(String schemaUrl)
    throws Exception {
        final SchemaFactory factory = SchemaFactory.newInstance(W3C_XML_SCHEMA_NS_URI);
        factory.setResourceResolver(new SchemaResolver());
        final Schema schema = factory.newSchema(new URL(schemaUrl));
        return schema.newValidator();
    }
}
