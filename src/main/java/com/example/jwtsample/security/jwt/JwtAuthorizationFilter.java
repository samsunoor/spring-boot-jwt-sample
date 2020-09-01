package com.example.jwtsample.security.jwt;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.jwtsample.security.SecurityConstant;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, JwtSpecification jwtSpecification) {
        super(authenticationManager);
        this.jwtSpecification = jwtSpecification;
    }

    private final JwtSpecification jwtSpecification;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        final var header = request.getHeader(SecurityConstant.AUTH_HEADER);
        if (header == null || !header.startsWith(SecurityConstant.BEARER_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authenticationToken = getAuthentication(request);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) throws JWTVerificationException {
        final var headerValue = request.getHeader(SecurityConstant.AUTH_HEADER);
        if (headerValue != null) {
            final var token = headerValue.replace(SecurityConstant.BEARER_PREFIX, "");
            final var subject = jwtSpecification.getJwtVerifier()
                    .verify(token)
                    .getSubject();

            if (subject != null) return new UsernamePasswordAuthenticationToken(subject, null, Collections.emptyList());

            return null;
        }

        return null;
    }
}
