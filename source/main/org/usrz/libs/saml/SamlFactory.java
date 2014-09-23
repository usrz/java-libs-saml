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

/**
 * A factory for <i>SAML</i> objects.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public interface SamlFactory {

    /**
     * Parse a request into a {@link SamlAuthnRequest} instance.
     *
     * @param request The base-64 encoded (possibly deflated) request.
     * @param inflate Whether the request was deflated or not.
     */
    public SamlAuthnRequest parseAuthnRequest(String request, boolean inflate);

    /**
     * Create a new {@link SamlResponseBuilder} associated with the given
     * {@link SamlAuthnRequest} instance.
     * <p>
     * By default, the {@link SamlResponseBuilder} will be prepared as follows:
     * </p>
     * <ul>
     *   <li>{@link SamlResponseBuilder#withInResponseTo(String)}
     *       <br>will be set to {@link SamlAuthnRequest#getID()}</li>
     *   <li>{@link SamlResponseBuilder#withDestination(URI)}, <br>
     *       {@link SamlResponseBuilder#withRecipient(URI)}, and <br>
     *       {@link SamlResponseBuilder#withAudience(URI)}<br>will be set to
     *       {@link SamlAuthnRequest#getAssertionConsumerServiceURL()}</li>
     * </ul>
     */
    public SamlResponseBuilder prepareResponse(SamlAuthnRequest request);

}