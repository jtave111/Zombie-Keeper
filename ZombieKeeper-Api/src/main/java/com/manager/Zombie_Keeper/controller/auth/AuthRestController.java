package com.manager.Zombie_Keeper.controller.auth;
import com.manager.Zombie_Keeper.dtos.auth.LoginDtos;
import com.manager.Zombie_Keeper.dtos.auth.RoleDtos;
import com.manager.Zombie_Keeper.dtos.auth.UserDtos;
import com.manager.Zombie_Keeper.dtos.auth.UserResponseDtos;
import com.manager.Zombie_Keeper.model.entity.auth.Role;
import com.manager.Zombie_Keeper.model.entity.auth.User;
import com.manager.Zombie_Keeper.repository.auth.RoleRepository;
import com.manager.Zombie_Keeper.repository.auth.UserRepository;
import com.manager.Zombie_Keeper.service.auth.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthRestController {

    private static final Logger logger = LoggerFactory.getLogger(AuthRestController.class);

    AuthService authService;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private UserRepository userRepository;


    public AuthRestController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody @Valid LoginDtos dto, HttpServletRequest request) {
        try {
            String token = authService.authenticateUser(dto, request);
            logger.info("Operator '{}' logged in successfully.", dto.getUsername());

            Map<String, Object> response = new HashMap<>();
            response.put("status", "AUTHORIZED");
            response.put("token", token);
            response.put("username", dto.getUsername());
            response.put("message", "Login successful");

            return ResponseEntity.ok(response);
            
        } catch (AuthenticationException e) {
            logger.warn("Failed login attempt for operator '{}'", dto.getUsername());

            Map<String, String> error = new HashMap<>();
            error.put("status", "UNAUTHORIZED");
            error.put("message", "Invalid credentials");

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body((Map) error);
        }
    }

    @PostMapping("/register")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> createAccount(@RequestBody @Valid UserDtos dto) {
        try {

            String plainPass = dto.getPassword();
            String passEncoder = encoder.encode(plainPass);
            Role roleUser = roleRepository.findByName(dto.getRole().getName()).get();

                    User user = new User(
                            dto.getUsername(),
                            passEncoder,
                            dto.getName(),
                            roleUser
                    );

            userRepository.save(user);
            logger.info("New operator account created: {}", dto.getUsername());

            return ResponseEntity.status(HttpStatus.CREATED).body("Account created");

        }catch (IllegalArgumentException e){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());

        }
    }

    @GetMapping("/profile")
    public User getActualUser(Authentication auth){

        return (User) auth.getPrincipal();
    }


    @GetMapping("/session-id")
    public ResponseEntity<String> getHttpSessionId(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session != null
            ? ResponseEntity.ok(session.getId())
            : ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No active session");
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResponseDtos>> listUsers() {
        List<UserResponseDtos> users = userRepository.findAll()
                .stream()
                .map(UserResponseDtos::new)
                .collect(Collectors.toList());
        return ResponseEntity.ok(users);
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> deleteUser(@PathVariable Long id, Authentication auth) {
        User caller = (User) auth.getPrincipal();
        if (caller.getId().equals(id))
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Cannot delete your own account");

        if (!userRepository.existsById(id))
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");

        userRepository.deleteById(id);
        logger.info("Operator account {} deleted by {}", id, caller.getUsername());
        return ResponseEntity.ok("User deleted");
    }

    @PutMapping("/users/{id}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserResponseDtos> updateUserRole(@PathVariable Long id, @RequestBody RoleDtos dto) {
        return userRepository.findById(id).map(user -> {
            Role role = roleRepository.findByName(dto.getName())
                    .orElseThrow(() -> new IllegalArgumentException("Role not found: " + dto.getName()));
            user.setRole(role);
            userRepository.save(user);
            logger.info("Role of user {} updated to {}", user.getUsername(), role.getName());
            return ResponseEntity.ok(new UserResponseDtos(user));
        }).orElse(ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @PutMapping("/users/{id}/password")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> resetPassword(@PathVariable Long id, @RequestBody Map<String, String> body) {
        String newPass = body.get("password");
        if (newPass == null || newPass.isBlank())
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Password is required");

        return userRepository.findById(id).map(user -> {
            user.setPassword(encoder.encode(newPass));
            userRepository.save(user);
            logger.info("Password reset for user {}", user.getUsername());
            return ResponseEntity.ok("Password updated");
        }).orElse(ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found"));
    }

    @GetMapping("/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Role>> listRoles() {
        return ResponseEntity.ok(roleRepository.findAll());
    }
}