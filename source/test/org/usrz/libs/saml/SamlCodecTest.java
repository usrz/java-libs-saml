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

import java.util.Arrays;
import java.util.Random;

import org.testng.annotations.Test;
import org.usrz.libs.testing.AbstractTest;

public class SamlCodecTest extends AbstractTest {

    @Test
    public void testSamlCodec() {
        final SamlCodec codec = new SamlCodec();
        byte[] original = new byte[4096];
        new Random().nextBytes(original);

        byte[] remix = null;
        for (int x = 0; x < 100; x ++) {
            final String string = codec.encode(original);
            assertNotNull(string, "Null encoded string");
            assertNotEquals(string, "", "Empty encoded string");
            remix = codec.decode(string);
            assertEquals(original, remix, "Arrays differ after " + x + " iterations");
        }
        assertTrue(Arrays.equals(original, remix), "Arrays differ at the end...");
    }
}