package com.example.jwtsample.security;

public class SecurityConstant {
    public static final String AUTH_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";

    public static final String JWT_SECRET = "anu";
    public static final String JWT_ISSUER = "com.example.jwt-sample.security";
    public static final String JWT_AUDIENCE = "com.example.jwt-sample";
    public static final long JWT_ACCESS_LIFETIME = 15L; //minutes
    public static final long JWT_REFRESH_LIFETIME = 6L; //days

}
