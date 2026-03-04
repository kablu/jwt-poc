# JWK POC — Complete Analysis & Implementation Guide

> **Author:** Kablu | **Date:** 2026-03-04 | **RFC:** 7517 (JWK), 7519 (JWT), 7591 (Dynamic Registration)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [JWK vs JWT — Core Difference](#2-jwk-vs-jwt--core-difference)
3. [JWKS Endpoint — Default URLs Comparison](#3-jwks-endpoint--default-urls-comparison)
4. [Repository Structure](#4-repository-structure)
5. [Auth Server — Implementation Detail](#5-auth-server--implementation-detail)
6. [Resource Server — Implementation Detail](#6-resource-server--implementation-detail)
7. [JWK POC (Original) — Implementation Detail](#7-jwk-poc-original--implementation-detail)
8. [Basic Auth Decoding](#8-basic-auth-decoding)
9. [Client ID & Secret — Who Maintains It](#9-client-id--secret--who-maintains-it)
10. [Multiple Resource Servers — Client Management](#10-multiple-resource-servers--client-management)
11. [Dynamic Client Registration — RFC 7591](#11-dynamic-client-registration--rfc-7591)
12. [Security Rules & Best Practices](#12-security-rules--best-practices)
13. [End-to-End Flow](#13-end-to-end-flow)
14. [How to Run](#14-how-to-run)
15. [API Reference](#15-api-reference)

---

## 1. Project Overview

### What We Built

This POC implements **RFC 7517 (JSON Web Key)** — Approach 1: **Spring Security OAuth2 Resource Server with Auto JWKS** verification.

```
jwt-poc/
├── auth-server/        → Spring Authorization Server (port 9000)
│                         10 RSA key pairs, JWKS endpoint, JWT issuance
├── resource-server/    → Spring Resource Server (port 8080)
│                         MovieController, JWT validation via JWKS
├── src/                → Original JWK POC (port 8080)
│                         Key rotation, JWKS, JWT signing service
└── docs/
    └── analysis.md     → This document
```

### Technology Stack

| Component       | Technology                                  |
|-----------------|---------------------------------------------|
| Framework       | Spring Boot 3.4.3                           |
| Build Tool      | Gradle 8.12                                 |
| Java Version    | Java 21 (LTS)                               |
| Auth Server     | Spring Security OAuth2 Authorization Server |
| PKI Library     | Nimbus JOSE + JWT 9.37.3                    |
| PKI (extended)  | BouncyCastle 1.78.1                         |
| Database        | H2 In-Memory                                |
| Security        | Spring Security 6.x                         |

---

## 2. JWK vs JWT — Core Difference

> **#1 confusion point** — Yeh dono alag problems solve karte hain

| Aspect           | JWK (RFC 7517)                        | JWT (RFC 7519)                        |
|------------------|---------------------------------------|---------------------------------------|
| **Kya hai**      | Cryptographic KEY                     | Signed/Encrypted TOKEN                |
| **Kya contain**  | RSA/EC key material (n, e, d...)      | Header + Payload + Signature          |
| **Purpose**      | Key distribution & management         | Authentication, Authorization         |
| **Endpoint**     | `/.well-known/jwks.json`              | `Authorization: Bearer <token>`       |
| **Signed?**      | No (yeh khud key hai)                 | Yes (JWK se sign hota hai)            |
| **Example**      | Auth server ki public key             | Access token, ID token                |

### Relationship — Kaise Kaam Karte Hain Saath

```
Auth Server
  │
  ├── RSA Key Pair Generate karta hai
  │      Private Key ──► JWT sign karta hai
  │      Public Key  ──► JWKS endpoint pe publish karta hai
  │
Resource Server
  │
  ├── JWKS fetch karta hai auth server se
  ├── Public key extract karta hai JWK se
  └── JWT signature verify karta hai us key se
```

### Analogy

```
JWK  = Taale ki duplicate chabi (public key) — sabko de do verify karne ke liye
JWT  = Sealed letter — claims ke saath, JWK se verify hoti hai
```

---

## 3. JWKS Endpoint — Default URLs Comparison

> **Common Misconception:** `/.well-known/jwks.json` Spring Authorization Server ka default nahi hai

| Server                        | Default JWKS URL                                          |
|-------------------------------|-----------------------------------------------------------|
| **Spring Authorization Server** | `/oauth2/jwks`                                          |
| **Keycloak**                  | `/realms/{realm}/protocol/openid-connect/certs`           |
| **Auth0**                     | `/.well-known/jwks.json`                                  |
| **Okta**                      | `/.well-known/oauth-authorization-server/v1/keys`         |
| **Hamara Auth Server**        | `/oauth2/jwks` (default) + `/.well-known/jwks.json` (custom) |

### Spring Authorization Server Default Endpoints

```
POST /oauth2/token                        ← JWT issue karo
GET  /oauth2/jwks                         ← JWKS (DEFAULT) ✅
GET  /oauth2/authorize                    ← Authorization endpoint
POST /oauth2/introspect                   ← Token introspection
POST /oauth2/revoke                       ← Token revocation
GET  /.well-known/openid-configuration    ← OIDC discovery
POST /connect/register                    ← Dynamic client registration (RFC 7591)
```

### Custom `/.well-known/jwks.json` Kyun Banaya?

```java
// Auth0 convention follow kiya — industry standard ban gaya hai
// Spring Authorization Server ka /oauth2/jwks aur hamara custom
// /.well-known/jwks.json — dono same 10 public keys serve karte hain

@GetMapping(value = "/.well-known/jwks.json")
public ResponseEntity<Map<String, Object>> getJwks() {
    return ResponseEntity.ok()
        .header("Cache-Control", "public, max-age=3600")
        .body(keyPairRegistryService.getPublicJwkSet().toJSONObject());
}
```

---

## 4. Repository Structure

```
jwt-poc/                                    (GitHub: kablu/jwt-poc)
│
├── jwk-plan.md                             Original brainstorming plan
│
├── docs/
│   └── analysis.md                         This document
│
├── auth-server/                            Spring Authorization Server
│   ├── build.gradle
│   ├── settings.gradle
│   ├── gradlew.bat
│   └── src/
│       ├── main/java/com/poc/authserver/
│       │   ├── AuthServerApplication.java
│       │   ├── config/
│       │   │   ├── AuthorizationServerConfig.java  ← JWKSource, RegisteredClient
│       │   │   └── SecurityConfig.java
│       │   ├── service/
│       │   │   └── KeyPairRegistryService.java     ← 10 RSA key pairs
│       │   └── controller/
│       │       └── JwksController.java             ← /.well-known/jwks.json
│       ├── main/resources/
│       │   └── application.yml                     ← port: 9000
│       └── test/java/com/poc/authserver/
│           ├── service/KeyPairRegistryServiceTest.java
│           └── controller/JwksControllerTest.java
│
├── resource-server/                        Spring Resource Server
│   ├── build.gradle
│   ├── settings.gradle
│   ├── gradlew.bat
│   └── src/
│       ├── main/java/com/poc/resourceserver/
│       │   ├── ResourceServerApplication.java
│       │   ├── config/
│       │   │   └── SecurityConfig.java             ← OAuth2 Resource Server config
│       │   ├── controller/
│       │   │   └── MovieController.java            ← provideMovieDetails
│       │   └── model/
│       │       └── Movie.java
│       ├── main/resources/
│       │   └── application.yml                     ← port: 8080, jwks-uri
│       └── test/java/com/poc/resourceserver/
│           └── controller/MovieControllerTest.java
│
└── src/                                    Original JWK POC Project
    ├── main/java/com/poc/jwkpoc/
    │   ├── JwkPocApplication.java
    │   ├── config/SecurityConfig.java
    │   ├── controller/
    │   │   ├── JwksController.java
    │   │   └── TokenController.java
    │   ├── service/
    │   │   ├── JwkService.java
    │   │   ├── JwkRotationService.java
    │   │   └── JwtSigningService.java
    │   ├── validator/AudienceValidator.java
    │   ├── entity/KeyRotationAudit.java
    │   └── repository/KeyRotationAuditRepository.java
    └── test/
        └── (21 unit tests + 1 integration test)
```

---

## 5. Auth Server — Implementation Detail

### Port: `9000`

### Core Responsibility

```
Auth Server kya karta hai:
  ✅ 10 RSA-2048 key pairs startup pe generate karta hai
  ✅ JWT tokens sign karta hai (private key use karta hai)
  ✅ JWKS endpoint pe 10 public keys publish karta hai
  ✅ Registered clients (clientId + secret) maintain karta hai
  ✅ Token issue karta hai jab valid client request kare
  ❌ Private keys KABHI expose nahi karta
```

### Key Class: `KeyPairRegistryService`

```java
@PostConstruct
public void generateAllKeyPairs() {
    for (int i = 1; i <= 10; i++) {
        String kid = String.format("auth-server-key-%02d", i);
        RSAKey rsaKey = new RSAKeyGenerator(2048)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .keyID(kid)
            .generate();
        fullKeyPairs.add(rsaKey);
    }
}

// Public JWKS — sirf public params (n, e) — private (d,p,q) NAHI
public JWKSet getPublicJwkSet() {
    return new JWKSet(
        fullKeyPairs.stream()
            .map(RSAKey::toPublicJWK)
            .collect(Collectors.toList())
    );
}
```

### Key Generation — 10 Key Pairs

```
kid: auth-server-key-01  →  RSA-2048, RS256, use=sig
kid: auth-server-key-02  →  RSA-2048, RS256, use=sig
kid: auth-server-key-03  →  RSA-2048, RS256, use=sig
...
kid: auth-server-key-10  →  RSA-2048, RS256, use=sig
```

### Registered Client (Static)

```java
RegisteredClient resourceClient = RegisteredClient
    .withId(UUID.randomUUID().toString())
    .clientId("resource-client")           // Username
    .clientSecret("{noop}secret")          // Password ({noop} = plain text, dev only)
    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
    .scope("movies:read")
    .scope("movies:write")
    .tokenSettings(TokenSettings.builder()
        .accessTokenTimeToLive(Duration.ofHours(1))
        .build())
    .build();
```

### JWKS Response — What Gets Returned

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "auth-server-key-01",
      "use": "sig",
      "alg": "RS256",
      "n":   "0vx7agoebGcQSuuPiLJXZpt...",
      "e":   "AQAB"
    },
    { "kid": "auth-server-key-02", ... },
    { "kid": "auth-server-key-03", ... },
    ...
    { "kid": "auth-server-key-10", ... }
  ]
}
```

> **NOTE:** `d`, `p`, `q`, `dp`, `dq`, `qi` — yeh private parameters KABHI response mein nahi aate

---

## 6. Resource Server — Implementation Detail

### Port: `8080`

### Core Responsibility

```
Resource Server kya karta hai:
  ✅ /api/movies endpoint protect karta hai (JWT required)
  ✅ JWT validate karta hai auth-server ke public keys se
  ✅ JWKS auto-fetch karta hai (Approach 1 — Spring handles it)
  ✅ kid mismatch pe auto-refetch JWKS
  ❌ ClientId/Secret se koi matlab nahi
  ❌ JWT sign nahi karta
```

### JWT Validation Flow — Approach 1

```
Client → GET /api/movies
         Authorization: Bearer eyJhbGc...
              │
              ▼
    NimbusJwtDecoder intercepts
              │
              ▼
    Cache mein JWKS hai? → YES → Use cached keys
                         → NO  → Fetch from auth-server
                                  GET http://localhost:9000/.well-known/jwks.json
              │
              ▼
    JWT header ka kid = "auth-server-key-05"
    JWKS mein match dhundo
              │
              ▼
    RSA public key se signature verify karo
              │
              ▼
    Issuer validate: iss == "http://localhost:9000" ?
              │
              ▼
    Expiry validate: exp > now ?
              │
              ✅ Access granted → Movie details return
```

### SecurityConfig — Approach 1

```java
@Bean
public JwtDecoder jwtDecoder() {
    NimbusJwtDecoder decoder = NimbusJwtDecoder
        .withJwkSetUri("http://localhost:9000/.well-known/jwks.json")
        .jwsAlgorithm(SignatureAlgorithm.RS256)
        .build();

    OAuth2TokenValidator<Jwt> issuerValidator =
        JwtValidators.createDefaultWithIssuer("http://localhost:9000");

    decoder.setJwtValidator(issuerValidator);
    return decoder;
}
```

### provideMovieDetails Endpoint

```
GET /api/movies
Authorization: Bearer <JWT from auth-server>

Response:
{
  "requestedBy":  "resource-client",
  "scope":        "movies:read",
  "issuedBy":     "http://localhost:9000",
  "tokenKid":     "auth-server-key-07",
  "totalMovies":  10,
  "movies": [
    { "id": 1, "title": "Inception",    "genre": "Sci-Fi",   "imdbRating": 8.8 },
    { "id": 2, "title": "Dark Knight",  "genre": "Action",   "imdbRating": 9.0 },
    { "id": 3, "title": "Interstellar", "genre": "Sci-Fi",   "imdbRating": 8.6 },
    { "id": 4, "title": "3 Idiots",     "genre": "Comedy",   "imdbRating": 8.4 },
    { "id": 5, "title": "Dangal",       "genre": "Biography","imdbRating": 8.4 },
    ...
  ]
}
```

---

## 7. JWK POC (Original) — Implementation Detail

### Port: `8080`

### Features

| Class                   | Responsibility                                           |
|-------------------------|----------------------------------------------------------|
| `JwkService`            | RSA/EC key generation (RFC 7517), min 2048-bit enforced  |
| `JwkRotationService`    | Thread-safe key store, monthly rotation, 2-key overlap   |
| `JwtSigningService`     | RS256 JWT issuance + Nimbus-based verification           |
| `AudienceValidator`     | RFC 7519 §4.1.3 audience claim validation                |
| `SecurityConfig`        | OAuth2 Resource Server + role extraction                 |
| `JwksController`        | `/.well-known/jwks.json` — public keys only              |
| `TokenController`       | `POST /api/auth/token`, `GET /api/protected/*`           |
| `KeyRotationAudit`      | H2 DB mein rotation audit trail                          |

### Key Rotation Strategy

```
Phase 1: Naya key generate karo → JWKS mein publish karo (purane ke saath)
Phase 2: Naye JWTs naye key (kid) se sign karo
Phase 3: Purane JWTs expire hone do (overlap window = 2 keys simultaneously)
Phase 4: Purana key JWKS se remove karo
```

---

## 8. Basic Auth Decoding

```
Authorization: Basic cmVzb3VyY2UtY2xpZW50OnNlY3JldA==

Base64 Decode:
  cmVzb3VyY2UtY2xpZW50OnNlY3JldA==  →  resource-client:secret

Format:
  Base64( clientId + ":" + clientSecret )
  Base64( "resource-client" + ":" + "secret" )

Manually encode karo:
  echo -n "resource-client:secret" | base64
  → cmVzb3VyY2UtY2xpZW50OnNlY3JldA==
```

### curl ke saath Token Fetch

```bash
# Option 1: Manual Base64
curl -X POST http://localhost:9000/oauth2/token \
  -H "Authorization: Basic cmVzb3VyY2UtY2xpZW50OnNlY3JldA==" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=movies:read"

# Option 2: -u flag (auto Base64 encode)
curl -X POST http://localhost:9000/oauth2/token \
  -u "resource-client:secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=movies:read"
```

---

## 9. Client ID & Secret — Who Maintains It

```
┌───────────────────────────────────────────────────────┐
│              auth-server (port 9000)                  │
│                                                       │
│  ✅ clientId maintain karta hai → "resource-client"   │
│  ✅ clientSecret maintain karta hai → "secret"        │
│  ✅ JWT sign karta hai (10 RSA keys se)               │
│  ✅ Token issue karta hai /oauth2/token pe            │
│  ✅ JWKS publish karta hai /.well-known/jwks.json     │
└───────────────────────────────────────────────────────┘
                    ↓ JWT token deta hai
┌───────────────────────────────────────────────────────┐
│            resource-server (port 8080)                │
│                                                       │
│  ❌ Client ID/Secret se koi matlab NAHI               │
│  ✅ Sirf JWT token validate karta hai                 │
│  ✅ JWKS se public key fetch karta hai                │
│  ✅ /api/movies protect karta hai                     │
└───────────────────────────────────────────────────────┘
```

### Real World Analogy

| Cheez              | Real World                                                   |
|--------------------|--------------------------------------------------------------|
| **auth-server**    | Bank — account aur password manage karta hai                 |
| **clientId:secret**| Bank ka username aur password                                |
| **JWT Token**      | Bank ka signed cheque                                        |
| **resource-server**| Shop — sirf cheque verify karta hai, bank ka kaam nahi karta |

---

## 10. Multiple Resource Servers — Client Management

### 3 Approaches

#### Approach 1 — InMemory (Dev/POC)

```java
return new InMemoryRegisteredClientRepository(
    buildClient("movie-service-client",     "movie-secret",     List.of("movies:read"),     60),
    buildClient("payment-service-client",   "payment-secret",   List.of("payments:read"),   30),
    buildClient("user-service-client",      "user-secret",      List.of("users:read"),      60),
    buildClient("order-service-client",     "order-secret",     List.of("orders:read"),     60),
    buildClient("inventory-service-client", "inventory-secret", List.of("inventory:read"), 120),
    buildClient("report-service-client",    "report-secret",    List.of("reports:read"),   120),
    buildClient("notification-service",     "notif-secret",     List.of("notif:send"),      60),
    buildClient("audit-service-client",     "audit-secret",     List.of("audit:read"),      60),
    buildClient("search-service-client",    "search-secret",    List.of("search:read"),     60),
    buildClient("admin-service-client",     "admin-secret",     List.of("admin:all"),       15)
);
```

#### Approach 2 — JDBC + H2/PostgreSQL (Production)

```java
@Bean
public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
    return new JdbcRegisteredClientRepository(jdbcTemplate);
}

@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

#### Approach 3 — application.yml se (Cleanest)

```yaml
clients:
  registered:
    - id: client-001
      clientId: movie-service-client
      clientSecret: movie-secret-2024
      scopes: [movies:read, movies:write]
      tokenExpiryMinutes: 60

    - id: client-002
      clientId: payment-service-client
      clientSecret: payment-secret-2024
      scopes: [payments:read]
      tokenExpiryMinutes: 30
    # ... upto 10
```

### 10 Resource Servers ka Flow

```
                   AUTH SERVER (port 9000)
                   10 Clients Registered
                          │
        ┌─────────────────┼──────────────────┐
        │                 │                  │
  movie-service     payment-service     user-service
  client-001        client-002          client-003
  scope:movies      scope:payments      scope:users
  1hr expiry        30min expiry        1hr expiry
        │                 │                  │
    port:8081         port:8082          port:8083
   /api/movies      /api/payments       /api/users
```

---

## 11. Dynamic Client Registration — RFC 7591

### Concept

```
Static Way:
  Developer manually code mein client add karta hai → restart ✋

Dynamic Way (RFC 7591):
  Naya Resource Server khud auth server ko hit karta hai →
  Auth Server automatically clientId + secret generate karke deta hai 🔄
```

### 3 Approaches

#### Approach A — Spring Built-in RFC 7591

```java
// Enable karo AuthorizationServerConfig mein
http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
    .oidc(oidc -> oidc
        .clientRegistrationEndpoint(Customizer.withDefaults()) // ← yahan
    );
```

```bash
# Naya resource server register kare:
curl -X POST http://localhost:9000/connect/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name":                "new-billing-service",
    "grant_types":                ["client_credentials"],
    "scope":                      "billing:read billing:write",
    "token_endpoint_auth_method": "client_secret_basic"
  }'

# Response — auto-generated credentials:
{
  "client_id":     "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "client_secret": "xK9mP2vQ8nL5rT7wY3jH6cF4bN1eA0s",
  "client_name":   "new-billing-service",
  "scope":         "billing:read billing:write"
}
```

#### Approach B — Custom Admin REST API

```
POST /api/admin/clients/register   ← Naya client register karo
GET  /api/admin/clients/{clientId} ← Client info dekho
DELETE /api/admin/clients/{id}     ← Client deregister karo
```

```java
// Request
{
  "clientId":           "new-billing-service",
  "scopes":             ["billing:read"],
  "tokenExpiryMinutes": 60
}

// Response — SECRET SIRF EK BAAR DIKHEGA!
{
  "success":      true,
  "clientId":     "new-billing-service",
  "clientSecret": "xK9mP2vQ8nL5rT7wY3j",
  "warning":      "Save this secret NOW — it will NEVER be shown again!"
}
```

#### Approach C — Resource Server Khud Register Kare (Self-Registration)

```java
// SelfRegistrationService.java — resource-server mein
@PostConstruct
public void registerWithAuthServer() {
    // Startup pe auth server ko hit karo
    ResponseEntity<Map> response = restTemplate.postForEntity(
        "http://localhost:9000/api/admin/clients/register",
        Map.of("clientId", "billing-service-client",
               "scopes",   List.of("billing:read")),
        Map.class
    );
    // Response se clientId + secret save karo in-memory
    String clientId     = (String) response.getBody().get("clientId");
    String clientSecret = (String) response.getBody().get("clientSecret");
    System.setProperty("dynamic.client.id",     clientId);
    System.setProperty("dynamic.client.secret", clientSecret);
}
```

### Dynamic Registration Complete Flow

```
Naya Resource Server Start Hota Hai
        │
        ▼
POST /api/admin/clients/register
{
  "clientId": "new-billing-service",
  "scopes":   ["billing:read"]
}
        │
        ▼
┌──────────────────────────────┐
│        AUTH SERVER           │
│  1. clientId unique check    │
│  2. Random secret generate   │
│  3. BCrypt encode            │
│  4. H2 DB mein save          │
│  5. Response return          │
└──────────────────────────────┘
        │
        ▼
Response:
{
  "clientId":     "new-billing-service",
  "clientSecret": "xK9mP2vQ8nL5rT7wY3j",  ← SIRF EK BAAR
  "warning":      "Save this NOW!"
}
        │
        ▼
POST /oauth2/token
Authorization: Basic <base64(clientId:secret)>
grant_type=client_credentials
        │
        ▼
JWT Token milta hai ✅
        │
        ▼
Protected Resource Access karo 🎬
```

### Approach Comparison

| Situation                | Approach            | Reason                          |
|--------------------------|---------------------|---------------------------------|
| **POC / Dev**            | A (RFC 7591)        | Industry standard, built-in     |
| **Internal Microservices**| B (Custom API)     | Full control, audit trail       |
| **Auto-scaling / K8s**   | C (Self-register)   | Kubernetes/Docker friendly      |
| **Enterprise**           | B + PostgreSQL      | Persistent + Admin control      |

---

## 12. Security Rules & Best Practices

### Private Key Protection

```
✅ getPublicJwkSet() always use karo JWKS endpoint pe
✅ toPublicJWK() private params strip kar deta hai (d, p, q, dp, dq, qi)
✅ Private keys sirf in-memory rakhein — never persist, never log
✅ Full JWKSet (with private keys) sirf Spring Auth Server internally use kare
```

### Key Size Requirements

```
RSA minimum:  2048 bits  (NIST SP 800-131A)
RSA preferred: 4096 bits (high security)
EC preferred:  P-256     (~128-bit security, equivalent to RSA-3072)
```

### Client Secret Rules

```
⚠️ clientSecret → SIRF EK BAAR dikhao (registration response mein)
   Uske baad BCrypt hash store hota hai — retrieve nahi ho sakta

⚠️ Production mein {noop} use mat karo — BCryptPasswordEncoder use karo

⚠️ Admin endpoints protect karo:
   POST /api/admin/clients/register → ROLE_ADMIN required

⚠️ Secret rotate karo periodically
   POST /api/admin/clients/{id}/rotate-secret

⚠️ Deregister karo jab service retire ho
   DELETE /api/admin/clients/{clientId}
```

### JWT Security

```
✅ Algorithm: RS256 (RSASSA-PKCS1-v1_5 + SHA-256)
✅ kid header: always set karo (key rotation support ke liye)
✅ iss claim: validate karo (trusted issuer check)
✅ exp claim: validate karo (expired token reject)
✅ aud claim: validate karo (wrong audience reject)
✅ HTTPS: production mein sirf HTTPS use karo
✅ Token expiry: short rakhein (1 hour max for client_credentials)
```

---

## 13. End-to-End Flow

### Complete JWT Flow — Step by Step

```
┌──────────────────────────────────────────────────────────────────┐
│                      STEP 1: Token Lena                          │
│                                                                  │
│  Client → POST http://localhost:9000/oauth2/token               │
│           Authorization: Basic cmVzb3VyY2UtY2xpZW50OnNlY3JldA== │
│           grant_type=client_credentials&scope=movies:read        │
│                          ↓                                       │
│           Auth Server validates clientId:secret                  │
│           Signs JWT with RSA private key (e.g., key-07)          │
│                          ↓                                       │
│  Response: {                                                     │
│    "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImF1dGgtc...", │
│    "token_type":   "Bearer",                                     │
│    "expires_in":   3600,                                         │
│    "scope":        "movies:read"                                 │
│  }                                                               │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│                  STEP 2: Protected Resource Access               │
│                                                                  │
│  Client → GET http://localhost:8080/api/movies                  │
│           Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZC...   │
│                          ↓                                       │
│  Resource Server intercepts JWT                                  │
│  Fetches JWKS: GET http://localhost:9000/.well-known/jwks.json   │
│  JWT kid="auth-server-key-07" → match 10 keys mein              │
│  RSA public key se signature verify                              │
│  Issuer validate: iss == "http://localhost:9000" ✅              │
│  Expiry validate: exp > now ✅                                   │
│                          ↓                                       │
│  ✅ 10 Movie Details Return                                      │
└──────────────────────────────────────────────────────────────────┘
```

### JWT Structure (Decoded)

```
Header:
{
  "alg": "RS256",
  "kid": "auth-server-key-07",
  "typ": "JWT"
}

Payload:
{
  "sub": "resource-client",
  "iss": "http://localhost:9000",
  "iat": 1709500800,
  "exp": 1709504400,
  "scope": "movies:read"
}

Signature:
  RSASSA-PKCS1-v1_5(
    base64url(header) + "." + base64url(payload),
    auth-server-key-07-PRIVATE-KEY
  )
```

---

## 14. How to Run

### Prerequisites

```
Java 21+
Gradle 8.12+ (or use included gradlew.bat)
```

### Step 1 — Auth Server Start Karo

```bash
cd D:/poc/jwt-poc/auth-server
./gradlew.bat bootRun

# Startup logs mein dikhega:
# ✅ Generated key pair [1/10]: kid=auth-server-key-01
# ✅ Generated key pair [2/10]: kid=auth-server-key-02
# ...
# ✅ All 10 RSA key pairs ready.
# Server started on port 9000
```

### Step 2 — Resource Server Start Karo

```bash
cd D:/poc/jwt-poc/resource-server
./gradlew.bat bootRun

# Server started on port 8080
```

### Step 3 — JWKS Verify Karo

```bash
curl http://localhost:9000/.well-known/jwks.json | python -m json.tool
# → 10 RSA public keys dikhenge
```

### Step 4 — Token Lao

```bash
curl -X POST http://localhost:9000/oauth2/token \
  -u "resource-client:secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=movies:read"
```

### Step 5 — Movies Access Karo

```bash
TOKEN="eyJhbGci..."   # Step 4 ka access_token

curl http://localhost:8080/api/movies \
  -H "Authorization: Bearer $TOKEN"

# → 10 movies return hongi ✅
```

### Step 6 — Tests Run Karo

```bash
# Auth Server tests
cd D:/poc/jwt-poc/auth-server
./gradlew.bat test

# Resource Server tests
cd D:/poc/jwt-poc/resource-server
./gradlew.bat test

# Original JWK POC tests
cd D:/poc/jwt-poc
./gradlew.bat test
```

---

## 15. API Reference

### Auth Server (port 9000)

| Method | Endpoint                             | Auth         | Description                      |
|--------|--------------------------------------|--------------|----------------------------------|
| `POST` | `/oauth2/token`                      | Basic Auth   | JWT access token issue karo      |
| `GET`  | `/oauth2/jwks`                       | Public       | JWKS — Spring default endpoint   |
| `GET`  | `/.well-known/jwks.json`             | Public       | JWKS — Custom endpoint (10 keys) |
| `GET`  | `/.well-known/openid-configuration`  | Public       | OIDC discovery metadata          |
| `POST` | `/connect/register`                  | Public*      | Dynamic client registration      |
| `GET`  | `/api/keys/info`                     | Public       | Key metadata (no key material)   |

### Resource Server (port 8080)

| Method | Endpoint                    | Auth         | Description                      |
|--------|-----------------------------|--------------|----------------------------------|
| `GET`  | `/api/movies`               | Bearer JWT   | provideMovieDetails — all movies |
| `GET`  | `/api/movies/{id}`          | Bearer JWT   | Single movie by ID               |
| `GET`  | `/api/movies/genre/{genre}` | Bearer JWT   | Movies filtered by genre         |
| `GET`  | `/actuator/health`          | Public       | Health check                     |

### Original JWK POC (port 8080)

| Method | Endpoint                       | Auth         | Description                       |
|--------|--------------------------------|--------------|-----------------------------------|
| `POST` | `/api/auth/token`              | Public       | JWT issue karo                    |
| `GET`  | `/.well-known/jwks.json`       | Public       | JWKS endpoint                     |
| `GET`  | `/api/protected/hello`         | Bearer JWT   | Authenticated greeting            |
| `GET`  | `/api/protected/me`            | Bearer JWT   | Current user JWT claims           |
| `POST` | `/api/admin/keys/rotate`       | ADMIN JWT    | Manual key rotation trigger       |
| `GET`  | `/api/admin/keys/audit`        | ADMIN JWT    | Key rotation audit log (H2)       |

---

## Git History

```
af54db2  feat: add auth-server and resource-server (Approach 1 - Auto JWKS)
30edb0f  feat: implement JWK POC - Requirement 1 (Spring OAuth2 Resource Server)
88155f9  Add files via upload (original jwk-plan.md)
```

---

*Generated from discussion on 2026-03-04 | RFC 7517, 7519, 7591 | Spring Boot 3.4.3*
