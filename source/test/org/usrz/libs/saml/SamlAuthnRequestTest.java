package org.usrz.libs.saml;
import static org.usrz.libs.saml.Saml.NameIdFormat.EMAIL_ADDRESS;
import static org.usrz.libs.saml.Saml.NameIdFormat.UNSPECIFIED;
import static org.usrz.libs.saml.Saml.ProtocolBinding.HTTP_POST;

import java.net.URI;
import java.util.Date;

import org.testng.annotations.Test;
import org.usrz.libs.testing.AbstractTest;

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

public class SamlAuthnRequestTest extends AbstractTest {

    @Test
    public void testSamlAuthnRequest()
    throws Exception {
        final String decoded = "fVLJTsMwEL0j8Q+W79mqHsBqggoIUYklooEDN9eZNAbHEzxOC3w9bgoCDiD5YL0Zv2U8s5PXzrANONJoc57FKWdgFdbarnN+X11ER/ykODyYkexML+aDb+0dvAxAnoWXlsRYyPngrEBJmoSVHZDwSizn11diEqeid+hRoeFscZ7zftWiVqifUDXQSoTaGiub51XdGzCmflKtbUA+c/bwZWuys7UgGmBhyUvrA5Rm0yg9jiZZlU3FNA3nkbPyU+lU232C/2yt9k0kLquqjMrbZTUSbHQN7iZ053yNuDYQK+x28qUk0psAN9IQcDYnAueDwTO0NHTgluA2WsH93VXOW+97Ekmy3W7jb5pEJgO59/1VES/GuYoxmvsx0P+Nyy9hXnxTz5IfVMXnf+1iLM5LNFq9sbkxuD1zIH3I4N0QIlyg66T/Wy2LsxHRddSMrWKw1IPSjYaas6TYq/5ejLAuHw==";
        final SamlAuthnRequest request = new SamlFactoryBase().parseAuthnRequest(decoded, true);

        assertEquals(request.getID(), "pbhoicoijocfehaoednlnafkbdplelldjchnfeak");
        assertEquals(request.getIssuer(), "google.com");
        assertEquals(request.getVersion(), "2.0");
        assertEquals(request.getIssueInstant(), new Date(1411310440000L)); // Sun Sep 21 23:40:40 JST 2014
        assertEquals(request.getNameIDPolicy(), UNSPECIFIED);
        assertEquals(request.getProtocolBinding(), HTTP_POST);
        assertEquals(request.getAssertionConsumerServiceURL(), URI.create("https://www.google.com/a/usrz.com/acs"));

    }

    @Test
    public void testSamlAuthnRequest2()
    throws Exception {
        final String encoded = "fVFdT8IwFH3nVyx979aOiaxhIwvEhASNAfXBt9JdwuLaYm+Lyq93TEnQRF/v\nOSfn406m77qNDuCwsaYgPGZkWg4mKHW7F1XwO7OC1wDoo45nUPRAQYIzwkps\nUBipAYVXYl3dLkUaM7F31ltlW3Ih+V8hEcH5LgCJFvOCnASOMnY9vgIY0Szd\nbijnkNENy4FuxkoO5YiPcp51fMQAC4NeGl+QlPGMspymwwc2FmkmePZMoqdz\nu86LRNXZbGYNBg1uDe7QKHhcLQuy836PIkkCumN8BFMDvsTK6kQqBYjJKRop\n+3lEb+3K39RJcol+L3nXdV7M723bqI+oalv7NnMgPRTEuwAkurFOS//3Sjzm\n/aWp6banCtCyaau6dl0skpRfrj9fVg4+AQ==";
        System.err.println(new String(new SamlCodec(true).decode(encoded)));
        final SamlAuthnRequest request = new SamlFactoryBase().parseAuthnRequest(encoded, true);

        assertEquals(request.getID(), "samlr-00785ee6-42fb-11e4-b09e-b8ca3a616914");
        assertEquals(request.getIssuer(), "usrz.zendesk.com");
        assertEquals(request.getVersion(), "2.0");
        assertEquals(request.getIssueInstant(), new Date(1411460654000L)); // Tue Sep 23 17:24:14 JST 2014
        assertEquals(request.getNameIDPolicy(), EMAIL_ADDRESS);
        assertEquals(request.getProtocolBinding(), null);
        assertEquals(request.getAssertionConsumerServiceURL(), URI.create("https://usrz.zendesk.com/access/saml"));

    }

}
