package com.aman.backend.controller;

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

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignupRequest request) {

        userService.registerUser(request);

        return ResponseEntity.ok("User Registered Successfully");
    }

}