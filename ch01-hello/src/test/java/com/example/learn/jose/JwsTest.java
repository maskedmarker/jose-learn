package com.example.learn.jose;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.HmacKey;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import java.security.SecureRandom;

public class JwsTest {

    /**
     * Producing Unprotected JWS
     */
    @Test
    public void noAlg() throws Exception {

        JwtClaims jwtClaims = new JwtClaims();
        jwtClaims.setSubject("7560755e-f45d-4ebb-a098-b8971c02ebef"); // set sub
        jwtClaims.setIssuedAtToNow();  // set iat
        jwtClaims.setExpirationTimeMinutesInTheFuture(10080); // set exp
        jwtClaims.setIssuer("https://codecurated.com"); // set iss
        jwtClaims.setStringClaim("name", "Brilian Firdaus");   // set name
        jwtClaims.setStringClaim("email", "brilianfird@gmail.com");//set email
        jwtClaims.setClaim("email_verified", true);  //set email_verified

        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.NONE);
        jws.setPayload(jwtClaims.toJson());

        String jwt = jws.getCompactSerialization(); //produce eyJ.. JWT
        System.out.println("JWT: " + jwt);
    }

    @Test
    public void consume() throws Exception {
        String jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiI3NTYwNzU1ZS1mNDVkLTRlYmItYTA5OC1iODk3MWMwMmViZWYiLCJpYXQiOjE2NTI1NTYyNjYsImV4cCI6MTY1MzE2MTA2NiwiaXNzIjoiaHR0cHM6Ly9jb2RlY3VyYXRlZC5jb20iLCJuYW1lIjoiQnJpbGlhbiBGaXJkYXVzIiwiZW1haWwiOiJicmlsaWFuZmlyZEBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZX0.";

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                // required for NONE alg
                .setJwsAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
                // disable signature requirement
                .setDisableRequireSignature()
                // require the JWT to have iat field
                .setRequireIssuedAt()
                // require the JWT to have exp field
                .setRequireExpirationTime()
                // expect the iss to be https://codecurated.com
                .setExpectedIssuer("https://codecurated.com")
                .build();

        // process JWT to jwt context
        JwtContext jwtContext = jwtConsumer.process(jwt);
        // get JWS object
        JsonWebSignature jws = (JsonWebSignature)jwtContext.getJoseObjects().get(0);
        // get claims
        JwtClaims jwtClaims = jwtContext.getJwtClaims();

        // print claims as map
        System.out.println(jwtClaims.getClaimsMap());
    }

    @Test
    public void JWS_HS256() throws Exception {

        // generate  key
        byte[] key = new byte[32];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key);
        HmacKey hmacKey = new HmacKey(key);

        JwtClaims jwtClaims = new JwtClaims();
        jwtClaims.setSubject("7560755e-f45d-4ebb-a098-b8971c02ebef"); // set sub
        jwtClaims.setIssuedAtToNow();  // set iat
        jwtClaims.setExpirationTimeMinutesInTheFuture(10080); // set exp
        jwtClaims.setIssuer("https://codecurated.com"); // set iss
        jwtClaims.setStringClaim("name", "Brilian Firdaus");   // set name
        jwtClaims.setStringClaim("email", "brilianfird@gmail.com");//set email
        jwtClaims.setClaim("email_verified", true);  //set email_verified

        JsonWebSignature jws = new JsonWebSignature();
        // Set alg header as HMAC_SHA256
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        // Set key to hmacKey
        jws.setKey(hmacKey);
        jws.setPayload(jwtClaims.toJson());

        String jwt = jws.getCompactSerialization(); //produce eyJ.. JWT

        // we don't need NO_CONSTRAINT and disable require signature anymore
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireIssuedAt()
                .setRequireExpirationTime()
                .setExpectedIssuer("https://codecurated.com")
                // set the verification key
                .setVerificationKey(hmacKey)
                .build();

        // process JWT to jwt context
        JwtContext jwtContext = jwtConsumer.process(jwt);
        // get JWS object
        JsonWebSignature consumedJWS = (JsonWebSignature)jwtContext.getJoseObjects().get(0);
        // get claims
        JwtClaims consumedJWTClaims = jwtContext.getJwtClaims();

        // print claims as map
        System.out.println(consumedJWTClaims.getClaimsMap());

        // Assert header, key, and claims
        Assertions.assertEquals(jws.getAlgorithmHeaderValue(), consumedJWS.getAlgorithmHeaderValue());
        Assertions.assertEquals(jws.getKey(), consumedJWS.getKey());
        Assertions.assertEquals(jwtClaims.toJson(), consumedJWTClaims.toJson());
    }
}
