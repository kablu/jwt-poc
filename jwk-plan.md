# JWK (JSON Web Key) — Complete Brainstorming & Implementation Plan

> RFC 7517 — JSON Web Key (JWK) | Author: Kablu | Date: 2026-03-01

---

## Table of Contents

1. [What is JWK? — RFC 7517 Deep Dive](#1-what-is-jwk--rfc-7517-deep-dive)
2. [JWK vs JWT — Key Differences](#2-jwk-vs-jwt--key-differences)
3. [JWK Structure Anatomy](#3-jwk-structure-anatomy)
4. [Key Types & Parameters](#4-key-types--parameters)
5. [JWKS — JSON Web Key Set](#5-jwks--json-web-key-set)
6. [JWK Use Cases](#6-jwk-use-cases)
7. [Spring Boot Implementation Approaches](#7-spring-boot-implementation-approaches)
8. [Implementation Deep Dives](#8-implementation-deep-dives)
9. [JWK in PKI / Certificate Context (Worldline/WLCA Relevance)](#9-jwk-in-pki--certificate-context-worldlinewlca-relevance)
10. [Security Considerations](#10-security-considerations)
11. [Tools, Libraries & Ecosystem](#11-tools-libraries--ecosystem)
12. [Decision Matrix — Which Approach to Use?](#12-decision-matrix--which-approach-to-use)
13. [Open Questions & Future Exploration](#13-open-questions--future-exploration)

---

## 1. What is JWK? — RFC 7517 Deep Dive

**JWK = JSON Web Key** — a JSON data structure that represents a **cryptographic key**.

RFC 7517 defines:
- A standard format to represent **public keys**, **private keys**, and **symmetric keys** in JSON
- A **JWK Set (JWKS)** — a collection of JWKs, typically served over HTTPS
- Companion to JOSE (JSON Object Signing and Encryption) suite:
  - RFC 7515 — JWS (JSON Web Signature)
  - RFC 7516 — JWE (JSON Web Encryption)
  - RFC 7517 — JWK (JSON Web Key) ← **this**
  - RFC 7518 — JWA (JSON Web Algorithms)
  - RFC 7519 — JWT (JSON Web Token)

### Core Concept

```
Cryptographic Key  ──►  JWK (JSON representation)  ──►  JWKS endpoint (URL)
```

**Why JSON?** Because HTTP APIs, microservices, and OAuth/OIDC flows needed a **language-agnostic, transport-friendly** key format. PEM/DER are binary/text but lack metadata. JWK adds rich metadata (algorithm, use, key ID).

### JWK vs PEM vs DER

| Aspect | JWK | PEM | DER |
|--------|-----|-----|-----|
| Format | JSON | Base64 text | Binary |
| Metadata | Rich (alg, use, kid, etc.) | None/minimal | None |
| Transport | HTTP-friendly | String-friendly | Binary |
| Human-readable | Yes | Partially | No |
| Standard | RFC 7517 | RFC 7468 / PKCS | ASN.1 |
| Interoperability | Web/OAuth/OIDC | TLS, SSH | Low-level libs |

---

## 2. JWK vs JWT — Key Differences

This is the #1 confusion point. They solve **different problems**.

| Aspect | JWK (RFC 7517) | JWT (RFC 7519) |
|--------|----------------|----------------|
| **What it is** | A cryptographic KEY | A CLAIM / TOKEN (signed/encrypted data) |
| **Contains** | RSA/EC/Symmetric key material | Header + Payload + Signature |
| **Purpose** | Key distribution & management | Authentication, authorization, data exchange |
| **Who uses it** | Authorization servers, JWKS endpoints | Clients, resource servers |
| **Signed?** | No (it IS the key or public key) | Yes (signed using JWK/key) |
| **Example** | Public key of auth server | Access token, ID token |
| **Endpoint** | `/.well-known/jwks.json` | Authorization header `Bearer <jwt>` |

### Relationship (How they work together)

```
Auth Server
  │
  ├── Generates RSA Key Pair
  │      Private Key ──► Signs JWT (access tokens)
  │      Public Key  ──► Published as JWK at /jwks.json endpoint
  │
Resource Server (your API)
  │
  ├── Fetches JWKS from auth server
  ├── Extracts public key from JWK
  └── Verifies JWT signature using that public key
```

**Analogy (Hinglish):**
- JWK = **Taala ki duplicate chabi** (public key copy) jo verify karne ke liye dete hain
- JWT = **Sealed letter** jisme claims hain, JWK se verify hoti hai

---

## 3. JWK Structure Anatomy

### Minimal RSA Public Key JWK

```json
{
  "kty": "RSA",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM...",
  "e": "AQAB",
  "kid": "2011-04-29",
  "use": "sig",
  "alg": "RS256"
}
```

### Complete JWK Parameter Reference

```
┌─────────────────────────────────────────────────────────────┐
│                     COMMON PARAMETERS                        │
│  kty  = Key Type        [REQUIRED] RSA | EC | oct | OKP     │
│  use  = Public Key Use  [OPTIONAL] sig | enc                 │
│  key_ops = Key Ops      [OPTIONAL] sign|verify|encrypt|...  │
│  alg  = Algorithm       [OPTIONAL] RS256|ES256|HS256...      │
│  kid  = Key ID          [OPTIONAL] unique identifier         │
│  x5u  = X.509 URL       [OPTIONAL] URL of X.509 cert        │
│  x5c  = X.509 Cert Chain[OPTIONAL] DER encoded certs        │
│  x5t  = X.509 Thumbprint[OPTIONAL] SHA-1 thumbprint          │
│  x5t#S256 = X.509 SHA-256 Thumbprint [OPTIONAL]             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   RSA KEY PARAMETERS                         │
│  n   = Modulus          (Base64urlUInt)                      │
│  e   = Exponent         (Base64urlUInt)                      │
│  d   = Private Exponent (Base64urlUInt) ← private only      │
│  p   = First Prime      (Base64urlUInt) ← private only      │
│  q   = Second Prime     (Base64urlUInt) ← private only      │
│  dp  = d mod (p-1)      (Base64urlUInt) ← private only      │
│  dq  = d mod (q-1)      (Base64urlUInt) ← private only      │
│  qi  = CRT Coefficient  (Base64urlUInt) ← private only      │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                  EC KEY PARAMETERS                           │
│  crv = Curve    P-256 | P-384 | P-521 | Ed25519 | Ed448     │
│  x   = X Coordinate (Base64url)                              │
│  y   = Y Coordinate (Base64url)                              │
│  d   = Private Key  (Base64url) ← private only              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│              SYMMETRIC KEY PARAMETERS (oct)                  │
│  k   = Key Value (Base64url encoded key bytes)               │
└─────────────────────────────────────────────────────────────┘
```

### RSA Private Key JWK (Full)

```json
{
  "kty": "RSA",
  "kid": "key-2024-01",
  "use": "sig",
  "alg": "RS256",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx...",
  "e": "AQAB",
  "d": "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH...",
  "p": "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQB...",
  "q": "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v...",
  "dp": "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3...",
  "dq": "s9lAH9fggBsoFR33s4ZEr0mvR1CkDU60MkUXF2IfDHqkj...",
  "qi": "GyM_p6JrXySiz1toFgKbWV-JdI3jT4s9E7m_P5A...",
  "x5c": ["MIIEpAIBAAKCAQEA0vx7agoebGcQSu..."]
}
```

### EC Key JWK (P-256)

```json
{
  "kty": "EC",
  "crv": "P-256",
  "kid": "ec-key-01",
  "use": "sig",
  "alg": "ES256",
  "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
}
```

---

## 4. Key Types & Parameters

### kty Values

| kty | Description | Algorithms | Use Case |
|-----|-------------|------------|----------|
| `RSA` | RSA keys | RS256, RS384, RS512, PS256, RSA-OAEP | Signatures, Encryption |
| `EC` | Elliptic Curve | ES256 (P-256), ES384 (P-384), ES512 (P-521) | Signatures |
| `oct` | Octet Sequence (symmetric) | HS256, HS384, HS512, AES | HMAC, AES-KW |
| `OKP` | Octet Key Pair (EdDSA) | Ed25519, Ed448, X25519, X448 | EdDSA, ECDH |

### use vs key_ops

```
use       = high-level intent
key_ops   = specific operations (more granular)

"use": "sig"   ↔  key_ops: ["sign", "verify"]
"use": "enc"   ↔  key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]

⚠️  RFC says: Don't use both `use` and `key_ops` together
```

### Algorithm Mapping (alg parameter)

```
RSA:
  RS256  = RSASSA-PKCS1-v1_5 + SHA-256
  RS384  = RSASSA-PKCS1-v1_5 + SHA-384
  RS512  = RSASSA-PKCS1-v1_5 + SHA-512
  PS256  = RSASSA-PSS + SHA-256
  PS384  = RSASSA-PSS + SHA-384
  PS512  = RSASSA-PSS + SHA-512

EC:
  ES256  = ECDSA + P-256 + SHA-256
  ES384  = ECDSA + P-384 + SHA-384
  ES512  = ECDSA + P-521 + SHA-512

Symmetric:
  HS256  = HMAC + SHA-256
  HS384  = HMAC + SHA-384
  HS512  = HMAC + SHA-512

EdDSA (OKP):
  EdDSA  = Edwards-curve DSA (Ed25519/Ed448)
```

---

## 5. JWKS — JSON Web Key Set

A **JWKS** (JWK Set) is a JSON object with a `keys` array containing multiple JWKs.

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "signing-key-2024",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGcQ...",
      "e": "AQAB"
    },
    {
      "kty": "EC",
      "kid": "ec-signing-key-2024",
      "use": "sig",
      "alg": "ES256",
      "crv": "P-256",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    },
    {
      "kty": "RSA",
      "kid": "encryption-key-2024",
      "use": "enc",
      "alg": "RSA-OAEP",
      "n": "sXchDaQebHnPiGvyDqgT...",
      "e": "AQAB"
    }
  ]
}
```

### JWKS Endpoint Pattern

```
GET /.well-known/jwks.json

Response Headers:
  Content-Type: application/json
  Cache-Control: public, max-age=3600
  Access-Control-Allow-Origin: *
```

### Key Rotation in JWKS

```
JWKS with 2 keys = key rotation in progress

Phase 1: Publish new key (both old + new in JWKS)
Phase 2: Start signing with new key (kid in JWT header)
Phase 3: Wait for old JWTs to expire
Phase 4: Remove old key from JWKS
```

---

## 6. JWK Use Cases

### Primary Use Cases

```
1. OAuth 2.0 / OIDC
   Authorization Server → publishes JWKS
   Resource Server     → fetches JWKS, verifies JWT
   Client              → fetches JWKS for id_token validation

2. Microservices JWT Verification
   API Gateway / Service Mesh → fetch JWKS from auth service
   Validate incoming JWT bearer tokens

3. Key Distribution
   Distribute public keys without PKI infrastructure
   Alternative to X.509 certificates in web contexts

4. JWE (JSON Web Encryption)
   Recipient publishes JWK (public key for encryption)
   Sender encrypts payload using recipient's public JWK

5. mTLS / Certificate Binding
   JWK thumbprint as certificate identifier
   RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication

6. ACME Protocol (Let's Encrypt)
   Account keys represented as JWK
   Challenge validation using JWK thumbprints

7. Post-Quantum Cryptography (future)
   ML-KEM, ML-DSA keys as JWK format
   Draft RFCs in progress
```

---

## 7. Spring Boot Implementation Approaches

### Overview of All Approaches

```
APPROACH 1: Spring Security OAuth2 Resource Server (Auto JWKS)
APPROACH 2: Nimbus JOSE + JWT Library (Manual)
APPROACH 3: Spring Authorization Server (Auth server with JWKS endpoint)
APPROACH 4: Custom JWK Endpoint + BouncyCastle
APPROACH 5: Spring Security with Custom JwtDecoder
APPROACH 6: Java Native (java.security) + Manual JWK parsing
APPROACH 7: Auth0 java-jwt + jwks-rsa-java
APPROACH 8: WebFlux / Reactive JWK Resolution
APPROACH 9: JWK with HSM (PKCS#11) — PKI/Payment context
```

---

## 8. Implementation Deep Dives

### Approach 1: Spring Security OAuth2 Resource Server (Auto JWKS)

**Best for:** Microservices that need to verify JWTs from an external auth server.

**Dependencies:**

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

**application.yml:**

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: https://auth-server.example.com/.well-known/jwks.json
          # OR
          issuer-uri: https://auth-server.example.com
```

**Security Config:**

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwkSetUri("https://auth-server.example.com/.well-known/jwks.json")
                )
            );
        return http.build();
    }

    // Optional: Custom JWT decoder with additional validation
    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder
            .withJwkSetUri("https://auth-server.example.com/.well-known/jwks.json")
            .jwsAlgorithm(SignatureAlgorithm.RS256)
            .build();

        // Custom validator
        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator("my-api");
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(
            "https://auth-server.example.com"
        );
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(
            withIssuer, audienceValidator
        );
        decoder.setJwtValidator(validator);
        return decoder;
    }
}
```

**Custom Audience Validator:**

```java
@Component
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private final String audience;

    public AudienceValidator(String audience) {
        this.audience = audience;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        OAuth2Error error = new OAuth2Error("invalid_token",
            "JWT doesn't contain required audience", null);
        return jwt.getAudience().contains(audience)
            ? OAuth2TokenValidatorResult.success()
            : OAuth2TokenValidatorResult.failure(error);
    }
}
```

**How Spring caches JWKS:**
```
First JWT request:
  → NimbusJwtDecoder fetches JWKS from URI
  → Caches the JWKSet in-memory
  → Verifies JWT signature

Subsequent requests:
  → Uses cached JWKS (5-minute TTL default)
  → On kid mismatch → refetches JWKS

Key Rotation Handling:
  → kid in JWT header not found in cache
  → Automatic re-fetch from JWKS endpoint
  → Verifies with new key
```

---

### Approach 2: Nimbus JOSE + JWT Library (Manual Control)

**Best for:** Full control over JWK generation, parsing, signing, verification.

**Dependencies:**

```xml
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>9.37.3</version>
</dependency>
```

**JWK Generation:**

```java
@Service
public class JwkService {

    // Generate RSA JWK
    public RSAKey generateRsaJwk(int keySize, String kid) throws JOSEException {
        RSAKeyGenerator generator = new RSAKeyGenerator(keySize)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .keyID(kid != null ? kid : UUID.randomUUID().toString());
        return generator.generate();
    }

    // Generate EC JWK
    public ECKey generateEcJwk(Curve curve, String kid) throws JOSEException {
        ECKeyGenerator generator = new ECKeyGenerator(curve)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.ES256)
            .keyID(kid != null ? kid : UUID.randomUUID().toString());
        return generator.generate();
    }

    // Generate Symmetric JWK (HMAC)
    public OctetSequenceKey generateSymmetricJwk(int keyBits, String kid) throws JOSEException {
        OctetSequenceKeyGenerator generator = new OctetSequenceKeyGenerator(keyBits)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.HS256)
            .keyID(kid != null ? kid : UUID.randomUUID().toString());
        return generator.generate();
    }

    // Convert KeyPair to JWK
    public RSAKey fromKeyPair(KeyPair keyPair, String kid) {
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey((RSAPrivateKey) keyPair.getPrivate())
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .keyID(kid)
            .build();
    }

    // Convert X.509 Certificate to JWK
    public RSAKey fromCertificate(X509Certificate cert, PrivateKey privateKey) throws JOSEException {
        return new RSAKey.Builder((RSAPublicKey) cert.getPublicKey())
            .privateKey(privateKey)
            .x509CertChain(Collections.singletonList(Base64.encode(cert.getEncoded())))
            .keyUse(KeyUse.SIGNATURE)
            .build();
    }

    // Parse JWK from JSON string
    public JWK parseJwk(String jwkJson) throws ParseException {
        return JWK.parse(jwkJson);
    }

    // Parse JWKS from JSON
    public JWKSet parseJwkSet(String jwksJson) throws ParseException {
        return JWKSet.parse(jwksJson);
    }
}
```

**JWT Signing with JWK:**

```java
@Service
public class JwtSigningService {

    private final RSAKey rsaJwk;

    public JwtSigningService(JwkService jwkService) throws JOSEException {
        this.rsaJwk = jwkService.generateRsaJwk(2048, "key-001");
    }

    public String createSignedJwt(String subject, Map<String, Object> claims,
                                   Duration expiry) throws JOSEException {
        JWSSigner signer = new RSASSASigner(rsaJwk);

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
            .subject(subject)
            .issuer("https://my-auth-server.com")
            .issueTime(new Date())
            .expirationTime(Date.from(Instant.now().plus(expiry)));

        claims.forEach(claimsBuilder::claim);

        SignedJWT signedJWT = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaJwk.getKeyID())
                .type(JOSEObjectType.JWT)
                .build(),
            claimsBuilder.build()
        );

        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    // Verify JWT
    public JWTClaimsSet verifyJwt(String token, JWKSet jwkSet)
            throws ParseException, JOSEException, BadJOSEException {

        ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor =
            new DefaultJWTProcessor<>();

        JWSKeySelector<SimpleSecurityContext> keySelector =
            new JWSVerificationKeySelector<>(JWSAlgorithm.RS256,
                new ImmutableJWKSet<>(jwkSet));

        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor.process(token, null);
    }
}
```

---

### Approach 3: Spring Authorization Server (Publish JWKS Endpoint)

**Best for:** Building your own OAuth2/OIDC authorization server.

**Dependencies:**

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-authorization-server</artifactId>
</dependency>
```

**Authorization Server Config:**

```java
@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("my-client")
            .clientSecret("{noop}secret")
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("read")
            .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(1))
                .build())
            .build();
        return new InMemoryRegisteredClientRepository(client);
    }

    // JWKSource — Spring Auth Server auto-exposes /oauth2/jwks
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws JOSEException {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
            .keyID("auth-server-key-001")
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .generate();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
            .issuer("https://my-auth-server.com")
            .jwkSetEndpoint("/oauth2/jwks")  // This is the JWKS endpoint
            .build();
    }
}
```

**Auto-exposed endpoints by Spring Auth Server:**
```
GET /oauth2/jwks                    → JWKS endpoint (public keys)
POST /oauth2/token                  → Token endpoint
GET /.well-known/openid-configuration → OIDC discovery
GET /oauth2/authorize               → Authorization endpoint
```

---

### Approach 4: Custom JWKS Endpoint with BouncyCastle

**Best for:** PKI systems, HSM integration, custom certificate-backed JWKs. **Most relevant for Worldline/WLCA.**

**Dependencies:**

```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk18on</artifactId>
    <version>1.78.1</version>
</dependency>
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpkix-jdk18on</artifactId>
    <version>1.78.1</version>
</dependency>
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>9.37.3</version>
</dependency>
```

**JWK from X.509 Certificate (PKI Integration):**

```java
@Service
public class CertificateToJwkService {

    /**
     * Convert X.509 cert chain to JWK with certificate thumbprint
     * Useful in WLCA/PKI scenarios where certs are stored in HSM
     */
    public RSAKey certificateToJwk(X509Certificate cert, PrivateKey privateKey,
                                    String kid) throws Exception {
        RSAPublicKey rsaPublicKey = (RSAPublicKey) cert.getPublicKey();

        Base64URL x5tS256 = computeSha256Thumbprint(cert);

        RSAKey.Builder builder = new RSAKey.Builder(rsaPublicKey)
            .keyID(kid != null ? kid : x5tS256.toString())
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .x509CertSHA256Thumbprint(x5tS256)
            .x509CertChain(encodeCertChain(cert));

        if (privateKey != null) {
            builder.privateKey((RSAPrivateKey) privateKey);
        }

        return builder.build();
    }

    private Base64URL computeSha256Thumbprint(X509Certificate cert) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] certBytes = cert.getEncoded();
        byte[] digest = md.digest(certBytes);
        return Base64URL.encode(digest);
    }

    private List<Base64> encodeCertChain(X509Certificate... certs) throws Exception {
        List<Base64> chain = new ArrayList<>();
        for (X509Certificate cert : certs) {
            chain.add(Base64.encode(cert.getEncoded()));
        }
        return chain;
    }

    /**
     * Load certificate from PEM string (BouncyCastle)
     */
    public X509Certificate loadCertFromPem(String pem) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        try (PemReader reader = new PemReader(new StringReader(pem))) {
            PemObject pemObject = reader.readPemObject();
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pemObject.getContent()));
        }
    }

    /**
     * Extract JWK thumbprint (RFC 7638)
     * Used for: certificate binding, ACME, OAuth DPoP
     */
    public String computeJwkThumbprint(JWK jwk) throws JOSEException {
        ThumbprintURI thumbprint = jwk.computeThumbprintURI();
        return thumbprint.toString();
    }
}
```

**HSM-backed JWKS (PKCS#11 Integration):**

```java
@Configuration
public class HsmJwkConfig {

    @Value("${hsm.library.path}")
    private String hsmLibraryPath;

    @Value("${hsm.slot.index:0}")
    private int slotIndex;

    /**
     * Load keys from HSM via PKCS#11 and expose as JWKSet
     * Relevant for Worldline PKI/HSM infrastructure
     */
    @Bean
    public JWKSet hsmBackedJwkSet() throws Exception {
        // Configure PKCS#11 provider
        String pkcs11Config = String.format(
            "name = HSM\nlibrary = %s\nslot = %d", hsmLibraryPath, slotIndex);

        Provider pkcs11Provider = Security.getProvider("SunPKCS11");
        Provider configuredProvider = pkcs11Provider
            .configure(pkcs11Config);
        Security.addProvider(configuredProvider);

        // Login to HSM
        KeyStore keyStore = KeyStore.getInstance("PKCS11", configuredProvider);
        keyStore.load(null, "hsm-pin".toCharArray());

        List<JWK> jwks = new ArrayList<>();

        // Enumerate keys in HSM
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                Certificate[] chain = keyStore.getCertificateChain(alias);
                if (chain != null && chain[0] instanceof X509Certificate cert) {
                    PublicKey publicKey = cert.getPublicKey();
                    if (publicKey instanceof RSAPublicKey rsaKey) {
                        JWK jwk = new RSAKey.Builder(rsaKey)
                            .keyID(alias)
                            .keyUse(KeyUse.SIGNATURE)
                            .x509CertChain(encodeCerts(chain))
                            .build();
                        jwks.add(jwk);
                    }
                }
            }
        }

        return new JWKSet(jwks);
    }

    private List<Base64> encodeCerts(Certificate[] certs) throws CertificateEncodingException {
        List<Base64> encoded = new ArrayList<>();
        for (Certificate cert : certs) {
            encoded.add(Base64.encode(cert.getEncoded()));
        }
        return encoded;
    }
}
```

**Custom JWKS REST Controller:**

```java
@RestController
@RequestMapping("/.well-known")
public class JwksController {

    private final JWKSet jwkSet;
    private final JWKSet privateJwkSet; // Keep private keys separate!

    public JwksController(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
        this.privateJwkSet = jwkSet; // full set for internal use
    }

    /**
     * Public JWKS endpoint — NEVER expose private keys!
     */
    @GetMapping(value = "/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> getJwks() {
        // toPublicJWKSet() strips all private key material
        return jwkSet.toPublicJWKSet().toJSONObject();
    }

    /**
     * OIDC Discovery endpoint
     */
    @GetMapping(value = "/openid-configuration", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> openidConfiguration(@Value("${spring.security.oauth2.authorizationserver.issuer}") String issuer) {
        return Map.of(
            "issuer", issuer,
            "jwks_uri", issuer + "/.well-known/jwks.json",
            "token_endpoint", issuer + "/oauth2/token",
            "authorization_endpoint", issuer + "/oauth2/authorize",
            "response_types_supported", List.of("code"),
            "subject_types_supported", List.of("public"),
            "id_token_signing_alg_values_supported", List.of("RS256", "ES256")
        );
    }
}
```

---

### Approach 5: Custom JwtDecoder with JWK Caching

```java
@Configuration
public class JwtDecoderConfig {

    @Bean
    public JwtDecoder customJwtDecoder() {
        // With custom caching, timeout, and proxy settings
        RestOperations restOperations = restTemplate();

        NimbusJwtDecoder decoder = NimbusJwtDecoder
            .withJwkSetUri("https://auth-server.example.com/.well-known/jwks.json")
            .restOperations(restOperations)
            .jwsAlgorithms(algorithms -> {
                algorithms.add(SignatureAlgorithm.RS256);
                algorithms.add(SignatureAlgorithm.ES256);
            })
            .cache(buildCache()) // Custom caffeine cache
            .build();

        return decoder;
    }

    private RestTemplate restTemplate() {
        HttpComponentsClientHttpRequestFactory factory =
            new HttpComponentsClientHttpRequestFactory();
        factory.setConnectTimeout(5000);
        factory.setReadTimeout(10000);
        RestTemplate rt = new RestTemplate(factory);
        return rt;
    }

    private Cache buildCache() {
        return Caffeine.newBuilder()
            .maximumSize(100)
            .expireAfterWrite(1, TimeUnit.HOURS)
            .build();
    }
}
```

---

### Approach 6: JWK Key Rotation Implementation

```java
@Service
public class JwkRotationService {

    private final AtomicReference<JWKSet> currentJwkSet = new AtomicReference<>();
    private final Map<String, RSAKey> keyStore = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() throws JOSEException {
        rotateKey("initial");
    }

    /**
     * Rotate signing key — keeps old keys for JWT validation during transition
     */
    @Scheduled(cron = "0 0 0 1 * *") // Monthly rotation
    public void rotateKey(String reason) throws JOSEException {
        String newKid = "key-" + Instant.now().toEpochMilli();
        RSAKey newKey = new RSAKeyGenerator(2048)
            .keyID(newKid)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .generate();

        keyStore.put(newKid, newKey);

        // Keep last 2 keys for validation (overlap period)
        if (keyStore.size() > 2) {
            String oldestKid = keyStore.keySet().stream()
                .sorted()
                .findFirst()
                .orElseThrow();
            keyStore.remove(oldestKid);
        }

        // Update published JWKS (public keys only)
        List<JWK> publicKeys = keyStore.values().stream()
            .map(RSAKey::toPublicJWK)
            .collect(Collectors.toList());

        currentJwkSet.set(new JWKSet(publicKeys));
        log.info("Key rotated. New kid: {}, reason: {}", newKid, reason);
    }

    public RSAKey getCurrentSigningKey() {
        // Return the most recently added key
        return keyStore.entrySet().stream()
            .max(Map.Entry.comparingByKey())
            .map(Map.Entry::getValue)
            .orElseThrow(() -> new IllegalStateException("No signing key available"));
    }

    public JWKSet getPublicJwkSet() {
        return currentJwkSet.get();
    }
}
```

---

### Approach 7: Reactive / WebFlux JWK Support

```java
@Configuration
public class ReactiveJwtConfig {

    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder() {
        return NimbusReactiveJwtDecoder
            .withJwkSetUri("https://auth-server.example.com/.well-known/jwks.json")
            .jwsAlgorithm(SignatureAlgorithm.RS256)
            .build();
    }
}

@Configuration
@EnableWebFluxSecurity
public class ReactiveSecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
                                                          ReactiveJwtDecoder decoder) {
        return http
            .authorizeExchange(auth -> auth
                .pathMatchers("/.well-known/**").permitAll()
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtDecoder(decoder))
            )
            .build();
    }
}
```

---

### Approach 8: JWK Thumbprint (RFC 7638)

**JWK Thumbprint = SHA-256 hash of canonical JWK JSON**

Used for:
- OAuth 2.0 DPoP (Demonstrating Proof of Possession) — RFC 9449
- ACME account key binding
- Certificate subject binding

```java
@Service
public class JwkThumbprintService {

    /**
     * Compute JWK Thumbprint per RFC 7638
     * Canonical form: {"crv":..., "kty":..., "x":..., "y":...} (sorted keys, no whitespace)
     */
    public String computeThumbprint(JWK jwk) throws JOSEException {
        ThumbprintURI thumbprintURI = jwk.computeThumbprintURI();
        return thumbprintURI.toString(); // Returns "urn:ietf:params:oauth:jwk-thumbprint:sha-256:..."
    }

    public Base64URL computeBase64Thumbprint(JWK jwk) throws JOSEException {
        return jwk.computeThumbprint(); // SHA-256 thumbprint as Base64URL
    }

    /**
     * DPoP Proof validation using JWK thumbprint
     */
    public boolean validateDpopProof(String dpopProof, String accessToken) throws Exception {
        SignedJWT dpopJwt = SignedJWT.parse(dpopProof);
        JWK jwk = dpopJwt.getHeader().getJWK();

        // Verify DPoP JWT signature using embedded JWK
        JWSVerifier verifier;
        if (jwk instanceof RSAKey rsaKey) {
            verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
        } else if (jwk instanceof ECKey ecKey) {
            verifier = new ECDSAVerifier(ecKey.toECPublicKey());
        } else {
            throw new IllegalArgumentException("Unsupported key type");
        }

        return dpopJwt.verify(verifier);
    }
}
```

---

### Approach 9: Post-Quantum JWK (Future-proofing)

```java
// Draft: ML-DSA (CRYSTALS-Dilithium) as JWK
// OKP key type extension for PQC algorithms
// Currently in IETF draft stage

// For now, hybrid approach: classical + PQC
@Service
public class HybridJwkService {

    // Composite key: RSA-2048 + ML-DSA-44
    // RFC draft: draft-ietf-jose-dilithium
    public void generateHybridKeyPair() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA", "BC");
        rsaGen.initialize(2048);
        KeyPair rsaPair = rsaGen.generateKeyPair();

        // ML-DSA (post-quantum) via BouncyCastle
        KeyPairGenerator mlDsaGen = KeyPairGenerator.getInstance("ML-DSA", "BC");
        mlDsaGen.initialize(new MLDSAParameterSpec(MLDSAParameterSpec.ml_dsa_44));
        KeyPair mlDsaPair = mlDsaGen.generateKeyPair();

        // Future: Both keys bundled in a composite JWK
    }
}
```

---

## 9. JWK in PKI / Certificate Context (Worldline/WLCA Relevance)

### JWK + X.509 Certificate Binding

```
X.509 Certificate  ←→  JWK
─────────────────────────────
Subject Public Key Info  ←→  n, e (RSA) or x, y (EC)
Certificate Serial       →   kid (recommended mapping)
SHA-256 Fingerprint      ←→  x5t#S256
Certificate Chain        ←→  x5c
Issuer DN                →   not directly, but can be custom claim
Key Usage                ←→  use / key_ops
```

### CMP Protocol + JWK

In CMP (Certificate Management Protocol) flows, JWK can be used to:
- Represent enrollment keys before certificate issuance
- Validate signatures in CMP messages using JWK-based verification
- Exchange public keys between RA and CA in JSON-native contexts

```java
/**
 * Convert CMP PKIMessage sender key to JWK for REST-based RA
 */
public JWK cmpPublicKeyToJwk(SubjectPublicKeyInfo spki) throws Exception {
    PublicKey publicKey = BouncyCastleProvider.getPublicKey(spki);
    if (publicKey instanceof RSAPublicKey rsaKey) {
        return new RSAKey.Builder(rsaKey)
            .keyUse(KeyUse.SIGNATURE)
            .build();
    }
    throw new UnsupportedOperationException("Unsupported key type: " + publicKey.getAlgorithm());
}
```

### ACME Protocol + JWK

ACME (used for automated certificate enrollment) uses JWK natively:

```java
// ACME account key = JWK
// JWK Thumbprint = account identifier
// JWS with JWK = signed ACME requests

public String createAcmeAccountRequest(ECKey accountKey, String directoryUrl)
        throws JOSEException {
    JWSSigner signer = new ECDSASigner(accountKey);

    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
        .jwk(accountKey.toPublicJWK())  // Include public JWK in header
        .build();

    JWSObject jws = new JWSObject(header,
        new Payload(Map.of(
            "termsOfServiceAgreed", true,
            "contact", List.of("mailto:admin@example.com")
        ).toString()));

    jws.sign(signer);
    return jws.serialize();
}
```

---

## 10. Security Considerations

### Critical Security Rules

```
❌ NEVER expose private key material in JWKS endpoint
   Always call jwkSet.toPublicJWKSet() before serving

❌ NEVER use weak key sizes
   RSA: minimum 2048-bit (prefer 4096 for long-lived)
   EC:  minimum P-256 (prefer P-384 for high security)

❌ NEVER skip kid validation
   JWT header kid → match in JWKS → use that key
   Never try all keys (timing attacks, DoS risk)

✅ ALWAYS set Cache-Control headers on JWKS endpoint
   Cache-Control: public, max-age=3600

✅ ALWAYS validate JWT claims (not just signature)
   iss, aud, exp, nbf, iat

✅ ALWAYS rotate keys regularly
   Signing keys: every 90 days
   Encryption keys: annually or after compromise

✅ ALWAYS serve JWKS over HTTPS
   HTTP JWKS = man-in-the-middle risk

✅ ALWAYS implement key pinning for internal services
   Don't blindly trust any JWKS endpoint
```

### JWKS Endpoint Security Headers

```java
@GetMapping("/.well-known/jwks.json")
public ResponseEntity<Map<String, Object>> getJwks() {
    return ResponseEntity.ok()
        .header("Cache-Control", "public, max-age=3600, must-revalidate")
        .header("Content-Security-Policy", "default-src 'none'")
        .header("X-Content-Type-Options", "nosniff")
        .header("Access-Control-Allow-Origin", "*")
        .body(jwkSet.toPublicJWKSet().toJSONObject());
}
```

### Key Compromise Response

```
1. Immediately remove compromised key from JWKS
2. Generate new key pair
3. Revoke all tokens signed with compromised key
4. Force re-authentication of all users
5. Audit logs for any suspicious token usage
6. Consider X.509 certificate revocation (CRL/OCSP) if cert-backed
```

---

## 11. Tools, Libraries & Ecosystem

### Java / Spring Libraries

| Library | Group | Purpose | Spring Compat |
|---------|-------|---------|---------------|
| Nimbus JOSE + JWT | `com.nimbusds:nimbus-jose-jwt` | Full JOSE stack | ✅ Used by Spring internally |
| Spring Security OAuth2 | `spring-boot-starter-oauth2-resource-server` | Resource server | ✅ Native |
| Spring Authorization Server | `spring-boot-starter-oauth2-authorization-server` | Auth server | ✅ Native |
| BouncyCastle | `org.bouncycastle:bcprov-jdk18on` | Crypto primitives | ✅ Manual |
| Auth0 java-jwt | `com.auth0:java-jwt` | JWT only | ✅ Manual |
| JJWT | `io.jsonwebtoken:jjwt-api` | JWT only | ✅ Manual |
| jose4j | `org.bitbucket.b_c:jose4j` | Full JOSE | ✅ Manual |

### Testing JWK

```java
// Test with in-memory RSA key
@TestConfiguration
public class TestJwkConfig {

    @Bean
    public JWKSource<SecurityContext> testJwkSource() throws JOSEException {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
            .keyID("test-key")
            .generate();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    // Generate test JWT for integration tests
    public String generateTestToken(RSAKey rsaKey, String subject) throws JOSEException {
        JWSSigner signer = new RSASSASigner(rsaKey);
        SignedJWT jwt = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
            new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer("http://localhost")
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .build()
        );
        jwt.sign(signer);
        return jwt.serialize();
    }
}
```

### CLI Tools

```bash
# Generate RSA JWK (using mkjwk.org or jose cli)
jose jwk gen -i '{"kty":"RSA","alg":"RS256","use":"sig"}' > my-key.json

# View JWK
cat my-key.json | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin), indent=2))"

# Fetch and inspect JWKS
curl -s https://auth-server.example.com/.well-known/jwks.json | jq .

# Generate EC JWK
jose jwk gen -i '{"kty":"EC","crv":"P-256","use":"sig"}'
```

---

## 12. Decision Matrix — Which Approach to Use?

```
╔══════════════════════════════╦═══════════════════════════════════╗
║ Scenario                     ║ Recommended Approach              ║
╠══════════════════════════════╬═══════════════════════════════════╣
║ Verify JWT from Keycloak/    ║ Approach 1: Spring Security       ║
║ Okta/Auth0/Cognito           ║ OAuth2 Resource Server            ║
╠══════════════════════════════╬═══════════════════════════════════╣
║ Build your own Auth Server   ║ Approach 3: Spring Auth Server    ║
╠══════════════════════════════╬═══════════════════════════════════╣
║ PKI / HSM / Certificate      ║ Approach 4: BouncyCastle +        ║
║ backed keys (WLCA)           ║ Custom JWKS + PKCS#11             ║
╠══════════════════════════════╬═══════════════════════════════════╣
║ Full manual JOSE control     ║ Approach 2: Nimbus JOSE + JWT     ║
╠══════════════════════════════╬═══════════════════════════════════╣
║ Reactive / WebFlux apps      ║ Approach 7: NimbusReactiveJwt     ║
╠══════════════════════════════╬═══════════════════════════════════╣
║ OAuth DPoP / ACME            ║ Approach 8: JWK Thumbprint        ║
╠══════════════════════════════╬═══════════════════════════════════╣
║ Key rotation needed          ║ Approach 6: JwkRotationService    ║
╠══════════════════════════════╬═══════════════════════════════════╣
║ Custom caching/proxy         ║ Approach 5: Custom JwtDecoder     ║
╚══════════════════════════════╩═══════════════════════════════════╝
```

---

## 13. Open Questions & Future Exploration

```
□ Post-Quantum JWK — When will ML-DSA / ML-KEM JWK be standardized?
  → Track: draft-ietf-jose-dilithium, draft-ietf-jose-kyber

□ JWK in WLCA/CMP — How to bridge CMP certificate enrollment with JWK-based REST APIs?
  → Design: CMP RA → receives JWK → converts to PKCS#10 CSR → sends to CA

□ JWK Thumbprint as Subject — OAuth 2.0 mTLS certificate-bound access tokens
  → RFC 8705 implementation in Spring

□ JWKS Performance — Caching strategy for high-throughput payment systems
  → Caffeine cache + async refresh + circuit breaker

□ JWK in Spring AI — Can agent authentication tokens use JWK-based verification?
  → Explore: Spring AI + OAuth2 + JWK for AI service auth

□ HSM Key Attestation as JWK Extension — Custom x5c-like field for HSM attestation
  → RFC 9334 (RATS) + JWK extension

□ Kubernetes Workload Identity + JWK
  → Service Account Token = JWKS endpoint per cluster
  → Explore for containerized WLCA components

□ JWK Federation (OpenID Connect Federation — RFC 9101)
  → Federation of JWKs across trust chains
  → Relevant for multi-party payment networks
```

---

## Quick Reference Cheat Sheet

```
JWK = One key (JSON)
JWKS = Multiple keys (JSON array under "keys")
JWKS Endpoint = GET /.well-known/jwks.json

Key Flow:
  Generate RSAKey → JWKSet → Expose via /jwks.json → Client verifies JWT

Critical Methods (Nimbus):
  RSAKey.toPublicJWK()      → strip private material
  JWKSet.toPublicJWKSet()   → strip all private keys
  jwk.computeThumbprint()   → RFC 7638 thumbprint
  JWK.parse(json)           → parse from string
  JWKSet.load(url)          → fetch JWKS from URL

Spring Auto-config:
  spring.security.oauth2.resourceserver.jwt.jwk-set-uri=URL
  → Fetches, caches, verifies everything automatically
```

---

*Plan Version: 1.0 | RFC 7517 | Spring Boot 3.x | Java 21*
