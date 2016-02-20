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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.util.Assert;

/**
 * @author Dave Syer
 *
 */
public class RsaSecretEncryptor implements BytesEncryptor, TextEncryptor, RsaKeyHolder {

	private static final String DEFAULT_ENCODING = "UTF-8";

	// The secret for encryption is random (so dictionary attack is not a danger)
	private final static String DEFAULT_SALT = "deadbeef";

	private String salt;

	private RsaAlgorithm algorithm = RsaAlgorithm.DEFAULT;

	private Charset charset;

	private PublicKey publicKey;

	private PrivateKey privateKey;

	private Charset defaultCharset;

	private boolean gcm;

	public RsaSecretEncryptor(RsaAlgorithm algorithm, String salt, boolean gcm) {
		this(RsaKeyHelper.generateKeyPair(), algorithm, salt, gcm);
	}

	public RsaSecretEncryptor(RsaAlgorithm algorithm, String salt) {
		this(RsaKeyHelper.generateKeyPair(), algorithm, salt);
	}

	public RsaSecretEncryptor(RsaAlgorithm algorithm, boolean gcm) {
		this(RsaKeyHelper.generateKeyPair(), algorithm, DEFAULT_SALT, gcm);
	}

	public RsaSecretEncryptor(RsaAlgorithm algorithm) {
		this(RsaKeyHelper.generateKeyPair(), algorithm);
	}

	public RsaSecretEncryptor() {
		this(RsaKeyHelper.generateKeyPair());
	}

	public RsaSecretEncryptor(KeyPair keyPair, RsaAlgorithm algorithm, String salt,
			boolean gcm) {
		this(DEFAULT_ENCODING, keyPair.getPublic(), keyPair.getPrivate(), algorithm,
				salt, gcm);
	}

	public RsaSecretEncryptor(KeyPair keyPair, RsaAlgorithm algorithm, String salt) {
		this(DEFAULT_ENCODING, keyPair.getPublic(), keyPair.getPrivate(), algorithm,
				salt, false);
	}

	public RsaSecretEncryptor(KeyPair keyPair, RsaAlgorithm algorithm) {
		this(DEFAULT_ENCODING, keyPair.getPublic(), keyPair.getPrivate(), algorithm);
	}

	public RsaSecretEncryptor(KeyPair keyPair) {
		this(DEFAULT_ENCODING, keyPair.getPublic(), keyPair.getPrivate());
	}

	public RsaSecretEncryptor(String pemData, RsaAlgorithm algorithm, String salt) {
		this(RsaKeyHelper.parseKeyPair(pemData), algorithm, salt);
	}

	public RsaSecretEncryptor(String pemData, RsaAlgorithm algorithm) {
		this(RsaKeyHelper.parseKeyPair(pemData), algorithm);
	}

	public RsaSecretEncryptor(String pemData) {
		this(RsaKeyHelper.parseKeyPair(pemData));
	}

	public RsaSecretEncryptor(PublicKey publicKey, RsaAlgorithm algorithm, String salt,
			boolean gcm) {
		this(DEFAULT_ENCODING, publicKey, null, algorithm, salt, gcm);
	}

	public RsaSecretEncryptor(PublicKey publicKey, RsaAlgorithm algorithm, String salt) {
		this(DEFAULT_ENCODING, publicKey, null, algorithm, salt, false);
	}

	public RsaSecretEncryptor(PublicKey publicKey, RsaAlgorithm algorithm) {
		this(DEFAULT_ENCODING, publicKey, null, algorithm);
	}

	public RsaSecretEncryptor(PublicKey publicKey) {
		this(DEFAULT_ENCODING, publicKey, null);
	}

	public RsaSecretEncryptor(String encoding, PublicKey publicKey, PrivateKey privateKey) {
		this(encoding, publicKey, privateKey, RsaAlgorithm.DEFAULT);
	}

	public RsaSecretEncryptor(String encoding, PublicKey publicKey,
			PrivateKey privateKey, RsaAlgorithm algorithm) {
		this(encoding, publicKey, privateKey, algorithm, DEFAULT_SALT, false);
	}

	public RsaSecretEncryptor(String encoding, PublicKey publicKey,
			PrivateKey privateKey, RsaAlgorithm algorithm, String salt, boolean gcm) {
		this.charset = Charset.forName(encoding);
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.defaultCharset = Charset.forName(DEFAULT_ENCODING);
		this.algorithm = algorithm;
		this.salt = isHex(salt) ? salt : new String(Hex.encode(salt
				.getBytes(this.defaultCharset)));
		this.gcm = gcm;
	}

	@Override
	public String getPublicKey() {
		return RsaKeyHelper.encodePublicKey((RSAPublicKey) this.publicKey, "application");
	}

	@Override
	public String encrypt(String text) {
		return new String(Base64.encode(encrypt(text.getBytes(this.charset))),
				this.defaultCharset);
	}

	@Override
	public String decrypt(String encryptedText) {
		Assert.state(this.privateKey != null,
				"Private key must be provided for decryption");
		return new String(decrypt(Base64.decode(encryptedText
				.getBytes(this.defaultCharset))), this.charset);
	}

	@Override
	public byte[] encrypt(byte[] byteArray) {
		return encrypt(byteArray, this.publicKey, this.algorithm, this.salt, this.gcm);
	}

	@Override
	public byte[] decrypt(byte[] encryptedByteArray) {
		return decrypt(encryptedByteArray, this.privateKey, this.algorithm, this.salt,
				this.gcm);
	}

	private static byte[] encrypt(byte[] text, PublicKey key, RsaAlgorithm alg,
			String salt, boolean gcm) {
		byte[] random = KeyGenerators.secureRandom(16).generateKey();
		BytesEncryptor aes = gcm ? Encryptors.stronger(new String(Hex.encode(random)),
				salt) : Encryptors.standard(new String(Hex.encode(random)), salt);
		try {
			final Cipher cipher = Cipher.getInstance(alg.getJceName());
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] secret = cipher.doFinal(random);
			ByteArrayOutputStream result = new ByteArrayOutputStream(text.length + 20);
			writeInt(result, secret.length);
			result.write(secret);
			result.write(aes.encrypt(text));
			return result.toByteArray();
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot encrypt", e);
		}
	}

	private static void writeInt(ByteArrayOutputStream result, int length)
			throws IOException {
		byte[] data = new byte[2];
		data[0] = (byte) ((length >> 8) & 0xFF);
		data[1] = (byte) (length & 0xFF);
		result.write(data);
	}

	private static int readInt(ByteArrayInputStream result) throws IOException {
		byte[] b = new byte[2];
		result.read(b);
		return ((b[0] & 0xFF) << 8) | (b[1] & 0xFF);
	}

	private static byte[] decrypt(byte[] text, PrivateKey key, RsaAlgorithm alg,
			String salt, boolean gcm) {
		ByteArrayInputStream input = new ByteArrayInputStream(text);
		ByteArrayOutputStream output = new ByteArrayOutputStream(text.length);
		try {
			int length = readInt(input);
			byte[] random = new byte[length];
			input.read(random);
			final Cipher cipher = Cipher.getInstance(alg.getJceName());
			cipher.init(Cipher.DECRYPT_MODE, key);
			String secret = new String(Hex.encode(cipher.doFinal(random)));
			byte[] buffer = new byte[text.length - random.length - 2];
			input.read(buffer);
			BytesEncryptor aes = gcm ? Encryptors.stronger(secret, salt) : Encryptors
					.standard(secret, salt);
			output.write(aes.decrypt(buffer));
			return output.toByteArray();
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot decrypt", e);
		}
	}

	private static boolean isHex(String input) {
		try {
			Hex.decode(input);
			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

}
