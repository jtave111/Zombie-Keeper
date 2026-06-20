package com.manager.Zombie_Keeper;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@SpringBootApplication
public class C2ServerApplication {

    public static void main(String[] args) {
        loadDotEnv();
        SpringApplication.run(C2ServerApplication.class, args);
    }

    private static void loadDotEnv() {
        Path env = findEnvFile();
        if (env == null) return;
        try {
            Files.lines(env).forEach(line -> {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) return;
                int idx = line.indexOf('=');
                if (idx < 1) return;
                String key = line.substring(0, idx).trim();
                String value = line.substring(idx + 1).trim();
                if (System.getProperty(key) == null) {
                    System.setProperty(key, value);
                }
            });
            System.out.println("Loaded .env from: " + env.toAbsolutePath());
        } catch (IOException e) {
            System.err.println("Warning: could not load .env: " + e.getMessage());
        }
    }

    private static Path findEnvFile() {
        Path cwd = Path.of(".env");
        if (Files.exists(cwd)) return cwd;
        try {
            Path classesDir = Path.of(C2ServerApplication.class
                    .getProtectionDomain().getCodeSource().getLocation().toURI());
            Path moduleEnv = classesDir.getParent().getParent().resolve(".env");
            if (Files.exists(moduleEnv)) return moduleEnv;
        } catch (Exception ignored) {}
        return null;
    }
}
