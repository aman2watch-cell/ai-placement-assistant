package com.aman.backend.controller;

import com.aman.backend.dto.LoginRequest;      // <-- NEW
import com.aman.backend.dto.LoginResponse;     // <-- NEW
import com.aman.backend.dto.SignupRequest;
import com.aman.backend.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }
    
    // ==========================
    // SIGNUP API
    // ==========================
    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignupRequest request) {

        userService.registerUser(request);

        return ResponseEntity.ok("User Registered Successfully");
    }

    // ======================================
    // NEW LOGIN API
    // ======================================
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {

        LoginResponse response = userService.loginUser(request);

        return ResponseEntity.ok(response);
    }
}