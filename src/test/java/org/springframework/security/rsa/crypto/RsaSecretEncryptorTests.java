/*
 * Copyright 2013-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.rsa.crypto;

import static org.junit.Assert.assertEquals;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import org.junit.Before;
import org.junit.Test;

/**
 * @author Dave Syer
 *
 */
public class RsaSecretEncryptorTests {

	private RsaSecretEncryptor encryptor = new RsaSecretEncryptor();

	@Before
	public void init() {
		LONG_STRING = SHORT_STRING + SHORT_STRING + SHORT_STRING + SHORT_STRING;
		for (int i = 0; i < 4; i++) {
			LONG_STRING = LONG_STRING + LONG_STRING;
		}
	}

	@Test
	public void roundTripKey() {
		PublicKey key = RsaKeyHelper.generateKeyPair().getPublic();
		String encoded = RsaKeyHelper.encodePublicKey((RSAPublicKey) key,
				"application");
		assertEquals(key, RsaKeyHelper.parsePublicKey(encoded));
	}

	@Test
	public void roundTrip() {
		assertEquals("encryptor",
				encryptor.decrypt(encryptor.encrypt("encryptor")));
	}

	@Test
	public void roundTripWithPublicKeyEncryption() {
		RsaSecretEncryptor encryptor = new RsaSecretEncryptor(this.encryptor.getPublicKey());
		RsaSecretEncryptor decryptor = this.encryptor;
		assertEquals("encryptor",
				decryptor.decrypt(encryptor.encrypt("encryptor")));
	}

	@Test(expected = IllegalStateException.class)
	public void publicKeyCannotDecrypt() {
		RsaSecretEncryptor encryptor = new RsaSecretEncryptor(this.encryptor.getPublicKey());
		assertEquals("encryptor",
				encryptor.decrypt(encryptor.encrypt("encryptor")));
	}

	@Test
	public void roundTripLongString() {
		assertEquals(LONG_STRING,
				encryptor.decrypt(encryptor.encrypt(LONG_STRING)));
	}

	private static final String SHORT_STRING = "Bacon ipsum dolor sit amet tail pork loin pork chop filet mignon flank fatback tenderloin boudin shankle corned beef t-bone short ribs. Meatball capicola ball tip short loin beef ribs shoulder, kielbasa pork chop meatloaf biltong porchetta bresaola t-bone spare ribs. Andouille t-bone sausage ground round frankfurter venison. Ground round meatball chicken ribeye doner tongue porchetta.";
	private static String LONG_STRING;
}
