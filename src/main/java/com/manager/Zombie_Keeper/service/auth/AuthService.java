package com.manager.Zombie_Keeper.service.auth;

import com.manager.Zombie_Keeper.dtos.auth.CreateAcRequest;
import com.manager.Zombie_Keeper.dtos.auth.LoginRequest;
import com.manager.Zombie_Keeper.model.entity.auth.Role;
import com.manager.Zombie_Keeper.model.entity.auth.User;
import com.manager.Zombie_Keeper.repository.auth.RoleRepository;
import com.manager.Zombie_Keeper.repository.auth.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final RoleRepository roleRepository;

    public AuthService(
            @Lazy AuthenticationManager authenticationManager,
            UserRepository userRepository,
            PasswordEncoder encoder,
            RoleRepository roleRepository) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.encoder = encoder;
        this.roleRepository = roleRepository;
    }

    public void authenticateUser(LoginRequest dto, HttpServletRequest request) {
      
        UsernamePasswordAuthenticationToken token = 
            new UsernamePasswordAuthenticationToken(dto.getUsername(), dto.getPassword());
        Authentication authentication = authenticationManager.authenticate(token);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);

        HttpSession session = request.getSession(true);
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
    }

    public void registerNewOperator(CreateAcRequest dto) {
        if (!dto.getPassword().equals(dto.getRepeetPassword())) {
            throw new IllegalArgumentException("Passwords do not match");
        }
        
        if (userRepository.findByUsername(dto.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already exists");
        }
        
        Role role = roleRepository.findByType(dto.getRole());
        if (role == null) {
            throw new IllegalArgumentException("Role not found");
        }

        User newUser = new User();
        newUser.setName(dto.getName());
        newUser.setUsername(dto.getUsername());
        newUser.setPassword(encoder.encode(dto.getPassword()));
        newUser.setRole(role);

        userRepository.save(newUser);
    }
}