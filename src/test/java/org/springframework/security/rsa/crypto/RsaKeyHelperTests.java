/*
 * Copyright 2023 the original author or authors.
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
import static org.junit.Assert.assertTrue;

import java.nio.charset.Charset;
import java.security.KeyPair;

import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.StreamUtils;

public class RsaKeyHelperTests {

	@Test
	public void parsePrivateKey() throws Exception {
		// ssh-keygen -m pem -b 1024 -f src/test/resources/fake.pem
		String pem = StreamUtils.copyToString(new ClassPathResource("/fake.pem", getClass()).getInputStream(),
				Charset.forName("UTF-8"));
		KeyPair result = RsaKeyHelper.parseKeyPair(pem);
		assertTrue(result.getPrivate().getEncoded().length > 0);
		assertEquals("RSA", result.getPrivate().getAlgorithm());
	}

	@Test
	public void parseSpaceyKey() throws Exception {
		String pem = StreamUtils.copyToString(new ClassPathResource("/spacey.pem", getClass()).getInputStream(),
				Charset.forName("UTF-8"));
		KeyPair result = RsaKeyHelper.parseKeyPair(pem);
		assertTrue(result.getPrivate().getEncoded().length > 0);
		assertEquals("RSA", result.getPrivate().getAlgorithm());
	}

	@Test
	public void parseBadKey() throws Exception {
		// ssh-keygen -m pem -b 1024 -f src/test/resources/fake.pem
		String pem = StreamUtils.copyToString(new ClassPathResource("/bad.pem", getClass()).getInputStream(),
				Charset.forName("UTF-8"));
		try {
			RsaKeyHelper.parseKeyPair(pem);
			throw new IllegalStateException("Expected IllegalArgumentException");
		} catch (IllegalArgumentException e) {
			assertTrue(e.getMessage().contains("PEM"));
		}
	}

}
