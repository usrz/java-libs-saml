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

/**
 * The base/default implementation of the {@link SamlFactory} interface.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class SamlFactoryBase implements SamlFactory {

    public SamlFactoryBase() {
        /* Nothing to do here */
    }

    @Override
    public SamlResponseBuilder prepareResponse(SamlAuthnRequest request) {
        notNull(request, "Null request");
        return new SamlResponseBuilder()
            .withInResponseTo(request.getID())
            .withDestination(request.getAssertionConsumerServiceURL())
            .withRecipient(request.getAssertionConsumerServiceURL())
            .withAudience(request.getAssertionConsumerServiceURL());
    }

    @Override
    public SamlAuthnRequest parseAuthnRequest(String request, boolean deflate) {
        return new SamlAuthnRequestParser().parse(notNull(request, "Null request"), deflate);
    }
}
