package com.example.jwtsample.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwtsample.feature.users.UserEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.Date;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        try {
            final var userEntity = new ObjectMapper().readValue(request.getInputStream(), UserEntity.class);
            return getAuthenticationManager()
                    .authenticate(
                            new UsernamePasswordAuthenticationToken(
                                    userEntity.getUsername(),
                                    userEntity.getPassword(),
                                    Collections.emptyList()
                            )
                    );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult
    ) {
        final var username = ((User) authResult.getPrincipal()).getUsername();
        final var expireDate = new Date(System.currentTimeMillis() + 864_000_000L);
        final var algorithm = Algorithm.HMAC512(SecurityConstant.AUTH_SECRET);
        final var token = JWT.create()
                .withSubject(username)
                .withExpiresAt(expireDate)
                .sign(algorithm);
        response.addHeader(SecurityConstant.AUTH_HEADER, SecurityConstant.BEARER_PREFIX + token);
    }
}
