package com.example.jwtsample.feature.users.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class LoginResponse {
    private final String accessToken;
    private final String refreshToken;
}
