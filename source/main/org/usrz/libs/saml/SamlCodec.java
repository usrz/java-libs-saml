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

import static java.util.zip.Deflater.BEST_COMPRESSION;
import static org.usrz.libs.utils.codecs.Base64Codec.Alphabet.STANDARD;

import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import org.usrz.libs.utils.Check;
import org.usrz.libs.utils.codecs.AbstractCodec;
import org.usrz.libs.utils.codecs.Base64Codec;
import org.usrz.libs.utils.codecs.Codec;

public class SamlCodec extends AbstractCodec {

    private static final Codec BASE_64 = new Base64Codec(STANDARD, true);

    public SamlCodec() {
        /* Nothing to do... */
    }

    @Override
    public String encode(byte[] data, int offset, int length) {
        final byte[] deflated = new byte[65536];

        final Deflater deflater = new Deflater(BEST_COMPRESSION, true);
        deflater.setInput(data, offset, length);
        deflater.finish();
        final int bytes = deflater.deflate(deflated);

        return BASE_64.encode(deflated, 0, bytes);
    }

    @Override
    public byte[] decode(String data)
    throws IllegalArgumentException {
        final byte[] deflated = BASE_64.decode(Check.notNull(data, "Null data to decode"));
        final byte[] inflated = new byte[65536];

        final Inflater inflater = new Inflater(true);
        inflater.setInput(deflated);
        final int length;
        try {
            length = inflater.inflate(inflated);
        } catch (DataFormatException exception) {
            throw new IllegalArgumentException("Unable to inflate data", exception);
        }

        final byte[] decoded = new byte[length];
        System.arraycopy(inflated, 0, decoded, 0, length);
        return decoded;
    }

}
