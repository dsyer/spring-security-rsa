This little project provides some RSA extensions to the base
[spring-security-crypto](https://github.com/spring-projects/spring-security/tree/master/crypto)
library. Currently supported: encryption and decryption with 2
algorithms wrapped up in the Spring Security Crypto interfaces
`TextEncryptor` and `BytesEncryptor`. Example round trip:

```java
TextEncryptor encryptor = new RsaSecretEncryptor();
String cipher = encryptor.encrypt("my message");
String message = encryptor.decrypt(cipher);
```

Above we create an encryptor with a random RSA key (the default
constructor), and use it to encrypt and then decrypt a message. the
default constructor is useful for testing, but for more durable use
cases you can inject a private key or a `KeyPair` using the other
constructors.

The encryption algorithm in the `RsaSecretEncryptor` is to generate a
random 16-byte password, and use that to encrypt the message. The
password is then itself RSA encrypted and prepended to the cipher
text. The cipher test is base64 encoded (if using the `TextEncryptor`
interface).

The other algorithm is in the `RsaRawEncryptor` which does raw RSA
encryption on the whole message. We recommend the
`RsaSecretEncryptor`.

N.B. if you need RSA signing and verification there are utilities
already available in
[spring-security-jwt](https://github.com/spring-projects/spring-security-oauth/tree/master/spring-security-jwt).

**Important Prerequisites:** to use Spring Security RSA
you need the full-strength JCE installed in your JVM (it's not there by default).
You can download the "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files"
from Oracle, and follow instructions for installation (essentially replace the 2 policy files
in the JRE lib/security directory with the ones that you downloaded).
