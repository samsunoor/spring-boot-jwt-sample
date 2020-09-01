package com.example.jwtsample.security.jwt;

import com.example.jwtsample.feature.users.UserEntity;
import com.example.jwtsample.feature.users.dto.LoginResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtSpecification jwtSpecification) {
        setAuthenticationManager(authenticationManager);
        this.jwtSpecification = jwtSpecification;
    }

    private final JwtSpecification jwtSpecification;

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
    ) throws IOException {
        final var username = ((User) authResult.getPrincipal()).getUsername();
        final var responseBody = new LoginResponse(generateAccessToken(username), generateRefreshToken(username));
        final var mapper = new ObjectMapper();
        response.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(mapper.writeValueAsString(responseBody));
    }

    private String generateAccessToken(String subject) {
        final var jwtCreatorBuilder = jwtSpecification.getAccessClaims();
        jwtCreatorBuilder.withSubject(subject);
        return jwtSpecification.sign(jwtCreatorBuilder);
    }

    private String generateRefreshToken(String subject) {
        final var jwtCreatorBuilder = jwtSpecification.getRefreshClaims();
        jwtCreatorBuilder.withSubject(subject);
        return jwtSpecification.sign(jwtCreatorBuilder);
    }
}
