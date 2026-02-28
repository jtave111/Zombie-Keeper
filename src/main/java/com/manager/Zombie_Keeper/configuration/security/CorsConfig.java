package com.manager.Zombie_Keeper.configuration.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
@Configuration
public class CorsConfig implements WebMvcConfigurer{
  @Override
    public void addCorsMappings(CorsRegistry registry) {
          registry.addMapping("/**")
            .allowedOrigins(
                "http://localhost:8080",
                "http://127.0.0.1:5500",
                "http://192.168.5.81:8080"
            )
            .allowedMethods("*")
            .allowedHeaders("*")
            .allowCredentials(true);
    }
}