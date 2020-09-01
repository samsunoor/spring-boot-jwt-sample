package com.example.jwtsample.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.example.jwtsample.security.SecurityConstant;

import java.util.Date;

public class JwtSpecificationImpl implements JwtSpecification {

    private final Algorithm algorithm = Algorithm.HMAC512(SecurityConstant.JWT_SECRET);
    private final JWTVerifier jwtVerifier = JWT.require(algorithm)
            .withIssuer(SecurityConstant.JWT_ISSUER)
            .withAudience(SecurityConstant.JWT_AUDIENCE)
            .build();

    @Override
    public JWTVerifier getJwtVerifier() {
        return jwtVerifier;
    }

    @Override
    public JWTCreator.Builder getAccessClaims() {
        final var expireDate = new Date(System.currentTimeMillis() + SecurityConstant.JWT_ACCESS_LIFETIME * 60_000L);
        return JWT.create()
                .withExpiresAt(expireDate)
                .withIssuer(SecurityConstant.JWT_ISSUER)
                .withAudience(SecurityConstant.JWT_AUDIENCE)
                .withNotBefore(new Date());
    }

    @Override
    public JWTCreator.Builder getRefreshClaims() {
        final var expireDate = new Date(System.currentTimeMillis() + SecurityConstant.JWT_REFRESH_LIFETIME * 86_400_000L);
        return JWT.create()
                .withExpiresAt(expireDate)
                .withIssuer(SecurityConstant.JWT_ISSUER)
                .withAudience(SecurityConstant.JWT_AUDIENCE)
                .withNotBefore(new Date());
    }

    @Override
    public String sign(JWTCreator.Builder builder) {
        return builder.sign(algorithm);
    }
}
