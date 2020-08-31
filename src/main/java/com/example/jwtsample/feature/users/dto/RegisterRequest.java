package com.example.jwtsample.feature.users.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class RegisterRequest {
    private final String username;
    private final String password;
}
