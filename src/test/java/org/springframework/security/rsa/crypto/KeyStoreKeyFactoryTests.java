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

import org.junit.Test;

import org.springframework.core.io.ClassPathResource;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Dave Syer
 *
 */
public class KeyStoreKeyFactoryTests {

	@Test
	public void initializeEncryptorFromKeyStore() throws Exception {
		char[] password = "foobar".toCharArray();
		KeyStoreKeyFactory factory = new KeyStoreKeyFactory(
				new ClassPathResource("keystore.jks"), password);
		RsaSecretEncryptor encryptor = new RsaSecretEncryptor(factory.getKeyPair("test"));
		assertTrue("Should be able to decrypt", encryptor.canDecrypt());
		assertEquals("foo", encryptor.decrypt(encryptor.encrypt("foo")));
	}

	@Test
	public void initializeEncryptorFromPkcs12KeyStore() throws Exception {
		char[] password = "letmein".toCharArray();
		KeyStoreKeyFactory factory = new KeyStoreKeyFactory(
				new ClassPathResource("keystore.pkcs12"), password);
		RsaSecretEncryptor encryptor = new RsaSecretEncryptor(
				factory.getKeyPair("mytestkey"));
		assertTrue("Should be able to decrypt", encryptor.canDecrypt());
		assertEquals("foo", encryptor.decrypt(encryptor.encrypt("foo")));
	}

	@Test
	public void initializeEncryptorFromTrustedCertificateInKeyStore() throws Exception {
		char[] password = "foobar".toCharArray();
		KeyStoreKeyFactory factory = new KeyStoreKeyFactory(
				new ClassPathResource("keystore.jks"), password);
		RsaSecretEncryptor encryptor = new RsaSecretEncryptor(factory.getKeyPair("testcertificate"));
		assertFalse("Should not be able to decrypt", encryptor.canDecrypt());
		assertNotEquals("foo", encryptor.encrypt("foo"));
	}

	@Test
	public void initializeEncryptorFromTrustedCertificateInPkcs12KeyStore() throws Exception {
		char[] password = "letmein".toCharArray();
		KeyStoreKeyFactory factory = new KeyStoreKeyFactory(
				new ClassPathResource("keystore.pkcs12"), password);
		RsaSecretEncryptor encryptor = new RsaSecretEncryptor(factory.getKeyPair("mytestcertificate"));
		assertFalse("Should not be able to decrypt", encryptor.canDecrypt());
		assertNotEquals("foo", encryptor.encrypt("foo"));
	}

}
