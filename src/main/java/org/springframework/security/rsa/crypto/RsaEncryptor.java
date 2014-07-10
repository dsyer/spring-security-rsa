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

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.util.Assert;

/**
 * @author Dave Syer
 *
 */
public class RsaEncryptor implements BytesEncryptor, TextEncryptor {

	public static final String ALGORITHM = "RSA";

	private static final String DEFAULT_ENCODING = "UTF-8";

	private Charset charset;

	private PublicKey publicKey;

	private PrivateKey privateKey;

	private Charset defaultCharset;

	public RsaEncryptor() {
		this(RsaKeyHelper.generateKeyPair());
	}

	public RsaEncryptor(KeyPair keyPair) {
		this(DEFAULT_ENCODING, keyPair.getPublic(), keyPair.getPrivate());
	}

	public RsaEncryptor(String pemData) {
		this(RsaKeyHelper.parseKeyPair(pemData));
	}

	public RsaEncryptor(PublicKey publicKey) {
		this(DEFAULT_ENCODING, publicKey, null);
	}
	
	public RsaEncryptor(String encoding, PublicKey publicKey,
			PrivateKey privateKey) {
		this.charset = Charset.forName(encoding);
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.defaultCharset = Charset.forName(DEFAULT_ENCODING);
	}
	
	public String getPublicKey() {
		return RsaKeyHelper.encodePublicKey((RSAPublicKey) publicKey, "application");
	}

	@Override
	public String encrypt(String text) {
		return new String(Base64.encode(encrypt(text.getBytes(charset))),
				defaultCharset);
	}

	@Override
	public String decrypt(String encryptedText) {
		Assert.state(privateKey!=null, "Private key must be provided for decryption");
		return new String(decrypt(Base64.decode(encryptedText
				.getBytes(defaultCharset))), charset);
	}

	@Override
	public byte[] encrypt(byte[] byteArray) {
		return encrypt(byteArray, publicKey);
	}

	@Override
	public byte[] decrypt(byte[] encryptedByteArray) {
		return decrypt(encryptedByteArray, privateKey);
	}

	private static byte[] encrypt(byte[] text, PublicKey key) {
		ByteArrayOutputStream output = new ByteArrayOutputStream(text.length);
		try {
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			int limit = Math.min(text.length, 117);
			int pos = 0;
			while (pos < text.length) {
				cipher.init(Cipher.ENCRYPT_MODE, key);
				cipher.update(text, pos, limit);
				pos += limit;
				limit = Math.min(text.length - pos, 117);
				byte[] buffer = cipher.doFinal();
				output.write(buffer, 0, buffer.length);
			}
			return output.toByteArray();
		} catch (RuntimeException e) {
			throw e;
		} catch (Exception e) {
			throw new IllegalStateException("Cannot encrypt", e);
		}
	}

	private static byte[] decrypt(byte[] text, PrivateKey key) {
		ByteArrayOutputStream output = new ByteArrayOutputStream(text.length);
		try {
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			int limit = Math.min(text.length, 128);
			int pos = 0;
			while (pos < text.length) {
				cipher.init(Cipher.DECRYPT_MODE, key);
				cipher.update(text, pos, limit);
				pos += limit;
				limit = Math.min(text.length - pos, 128);
				byte[] buffer = cipher.doFinal();
				output.write(buffer, 0, buffer.length);
			}
			return output.toByteArray();
		} catch (RuntimeException e) {
			throw e;
		} catch (Exception e) {
			throw new IllegalStateException("Cannot decrypt", e);
		}
	}

}
