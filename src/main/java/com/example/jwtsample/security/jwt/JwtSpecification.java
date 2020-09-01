package com.example.jwtsample.security.jwt;

import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.interfaces.JWTVerifier;

public interface JwtSpecification {

    JWTVerifier getJwtVerifier();

    JWTCreator.Builder getAccessClaims();

    JWTCreator.Builder getRefreshClaims();

    String sign(JWTCreator.Builder builder);

}
