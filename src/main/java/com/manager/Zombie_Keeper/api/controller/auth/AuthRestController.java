package com.manager.Zombie_Keeper.api.controller.auth;

import com.manager.Zombie_Keeper.dtos.auth.CreateAcRequest;
import com.manager.Zombie_Keeper.dtos.auth.LoginRequest;
import com.manager.Zombie_Keeper.service.auth.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthRestController {

    private static final Logger logger = LoggerFactory.getLogger(AuthRestController.class);

    AuthService authService;


    public AuthRestController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody @Valid LoginRequest dto, HttpServletRequest request) {
        try {
            authService.authenticateUser(dto, request);
            logger.info("Operator '{}' logged in successfully.", dto.getUsername());
            return ResponseEntity.ok("AUTHORIZED");
            
        } catch (AuthenticationException e) {
            logger.warn("Failed login attempt for operator '{}'", dto.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    @PostMapping("/register")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> createAccount(@RequestBody @Valid CreateAcRequest dto) {
        try {
            authService.registerNewOperator(dto);
            logger.info("New operator account created: {}", dto.getUsername());
            return ResponseEntity.status(HttpStatus.CREATED).body("User created successfully");
            
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    @GetMapping("/session-id")
    public ResponseEntity<String> getHttpSessionId(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session != null 
            ? ResponseEntity.ok(session.getId()) 
            : ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No active session");
    }

    
}