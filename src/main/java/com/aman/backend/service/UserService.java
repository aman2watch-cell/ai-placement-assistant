package com.aman.backend.service;

import com.aman.backend.dto.LoginRequest;
import com.aman.backend.dto.LoginResponse;
import com.aman.backend.dto.SignupRequest;
import com.aman.backend.entity.User;
import com.aman.backend.repository.UserRepository;
import com.aman.backend.security.JwtUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public UserService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    // =========================================
    // USER REGISTRATION
    // =========================================
    public void registerUser(SignupRequest request) {

        // Check if email already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        User user = new User();

        user.setFullName(request.getFullName());
        user.setEmail(request.getEmail());

        // Encrypt password before saving
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        user.setRole(request.getRole());

        userRepository.save(user);
    }

    // =========================================
    // USER LOGIN
    // =========================================
    public LoginResponse loginUser(LoginRequest request) {

        // Find user by email
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() ->
                        new RuntimeException("Invalid email or password"));

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid email or password");
        }

        // Generate JWT Token
        String token = jwtUtil.generateToken(user.getEmail());

        // Return token
        return new LoginResponse(token);
    }
}
