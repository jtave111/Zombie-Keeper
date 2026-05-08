package com.manager.Zombie_Keeper.service.auth;

import com.manager.Zombie_Keeper.dtos.auth.LoginDtos;
import com.manager.Zombie_Keeper.model.entity.auth.User;
import com.manager.Zombie_Keeper.repository.auth.UserRepository;
import com.manager.Zombie_Keeper.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final JwtUtil jwtUtil;

    public AuthService(UserRepository userRepository, PasswordEncoder encoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.encoder = encoder;
        this.jwtUtil = jwtUtil;
    }

    public String authenticateUser(LoginDtos dto, HttpServletRequest request) {
        User user = userRepository.findByUsername(dto.getUsername())
                .orElseThrow(() -> {
                    logger.warn("Login failed: User '{}' not found", dto.getUsername());
                    return new UsernameNotFoundException("User not found");
                });

        if (!encoder.matches(dto.getPassword(), user.getPassword())) {
            logger.warn("Login failed: Invalid password for user '{}'", dto.getUsername());
            throw new BadCredentialsException("Invalid credentials");
        }

        String token = jwtUtil.generateToken(user);


        Authentication authentication = new PreAuthenticatedAuthenticationToken(
                user,
                token,
                user.getAuthorities()
        );

        // 4. Salva no SecurityContext
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);

        // 5. Salva na sessão HTTP
        HttpSession session = request.getSession(true);
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);

        logger.info("User '{}' authenticated successfully", user.getUsername());

        return token;
    }
}