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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;

import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 *
 */
public class KeyStoreKeyFactory {

	private Resource resource;
	private char[] password;
	private KeyStore store;
	private Object lock = new Object();
	private String type;

	public KeyStoreKeyFactory(Resource resource, char[] password) {
		this(resource, password, type(resource));
	}

	private static String type(Resource resource) {
		String ext = StringUtils.getFilenameExtension(resource.getFilename());
		return ext == null ? "jks" : ext;
	}

	public KeyStoreKeyFactory(Resource resource, char[] password, String type) {
		this.resource = resource;
		this.password = password;
		this.type = type;
	}

	public KeyPair getKeyPair(String alias) {
		return getKeyPair(alias, password);
	}

	public KeyPair getKeyPair(String alias, char[] password) {
		try {
			synchronized (lock) {
				if (store == null) {
					synchronized (lock) {
						store = KeyStore.getInstance(type);
						store.load(resource.getInputStream(), this.password);
					}
				}
			}
			RSAPrivateCrtKey key = (RSAPrivateCrtKey) store.getKey(alias, password);
			RSAPublicKeySpec spec = new RSAPublicKeySpec(key.getModulus(),
					key.getPublicExponent());
			PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
			return new KeyPair(publicKey, key);
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot load keys from store: " + resource,
					e);
		}
	}

}
