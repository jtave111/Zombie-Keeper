package com.manager.Zombie_Keeper.configuration.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity 
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
           
            .csrf(csrf -> csrf.disable())
            
            // Configuramos a sessão para ser criada quando necessário, ex login no JavaFX
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            
            .authorizeHttpRequests(auth -> auth
                
                // 1. ROTAS PÚBLICAS (Operador tentando logar)
                .requestMatchers("/api/auth/login").permitAll()
                
                // TODO definir ROTAS DOS ZUMBIS Malwares precisam conectar sem fazer login
                // Qualquer requisição para /api/c2/... passa direto pelo Spring Security
                .requestMatchers("/api/c2/**").permitAll()
                
                // 3. TODO O RESTO (Qualquer outra tentativa de acesso web exige estar logado)
                .anyRequest().authenticated()
            );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}