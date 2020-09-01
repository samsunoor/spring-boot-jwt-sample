package com.example.jwtsample.feature.users;

import com.example.jwtsample.feature.users.dto.RegisterRequest;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
@AllArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody RegisterRequest registerRequest) {
        final var username = registerRequest.getUsername();
        final var password = bCryptPasswordEncoder.encode(registerRequest.getPassword());
        final var userEntity = new UserEntity(username, password);
        userRepository.save(userEntity);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @GetMapping("/me")
    public ResponseEntity<String> userDetails() {
        return new ResponseEntity<>("OK", HttpStatus.OK);
    }
}
