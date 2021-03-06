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

import org.usrz.libs.saml.Saml.NameIdFormat;
import org.usrz.libs.saml.Saml.ProtocolBinding;

/**
 * A wrapper interface around a <i>SAML Authorization Request</i>.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public interface SamlAuthnRequest {

    /** The unique <i>ID</i> of the request. */
    public String getID();
    /** The <i>issuer</i> of the request. */
    public String getIssuer();
    /** The <i>version</i> of the request. */
    public String getVersion();
    /** The <i>instant</i> of the request as a {@link Date}. */
    public Date getIssueInstant();
    /** The <i>format</i> of the subjects as a {@link NameIdFormat}. */
    public NameIdFormat getNameIDPolicy();
    /** The <i>protocol</i> for the response as a {@link ProtocolBinding}. */
    public ProtocolBinding getProtocolBinding();
    /** The <i>location</i> where the request should be sent a {@link URI}. */
    public URI getAssertionConsumerServiceURL();

}
