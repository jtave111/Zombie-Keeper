package com.manager.Zombie_Keeper.configuration;

import com.manager.Zombie_Keeper.model.entity.auth.Role;
import com.manager.Zombie_Keeper.model.entity.auth.User;
import com.manager.Zombie_Keeper.repository.auth.RoleRepository;
import com.manager.Zombie_Keeper.repository.auth.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * DataInitializer — executa uma única vez ao subir a aplicação.
 *
 * Responsabilidades:
 *  1. Garantir que as roles base (ADMIN, OPERATOR) existam no banco.
 *  2. Criar o usuário administrador inicial se ainda não existir.
 *
 * Todas as operações são idempotentes: reiniciar a aplicação não duplica dados.
 *
 * Credenciais do admin são lidas do arquivo .env (nunca hardcoded aqui).
 * Variáveis necessárias:
 *   ADMIN_USERNAME — login do administrador
 *   ADMIN_PASSWORD — senha em texto plano (será armazenada com BCrypt)
 *   ADMIN_NAME     — nome de exibição do administrador
 *
 * Se qualquer uma das três variáveis estiver ausente, a criação do admin é
 * ignorada e um aviso é exibido no log — as roles ainda são criadas normalmente.
 */
@Component
public class DataInitializer {
/*
    // Lidas do .env via System.setProperty() em C2ServerApplication.loadDotEnv()
    @Value("${ADMIN_USERNAME:}")
    private String adminUsername;

    @Value("${ADMIN_PASSWORD:}")
    private String adminPassword;

    @Value("${ADMIN_NAME:}")
    private String adminName;

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(RoleRepository roleRepository,
                           UserRepository userRepository,
                           PasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(ApplicationArguments args) {
        // Passo 1: garantir que as roles existam antes de qualquer coisa.
        // findByName + orElseGet = só insere se não existir.
        Role adminRole = ensureRole("ADMIN");
        ensureRole("OPERATOR");

        // Passo 2: criar o admin inicial apenas se as variáveis estiverem definidas.
        if (adminUsername.isBlank() || adminPassword.isBlank() || adminName.isBlank()) {
            System.out.println("[DataInitializer] ADMIN_USERNAME / ADMIN_PASSWORD / ADMIN_NAME não configurados no .env — usuário admin não foi criado.");
            return;
        }

        // Só cria se ainda não existir um usuário com esse username.
        userRepository.findByUsername(adminUsername).orElseGet(() -> {
            User admin = new User(
                    adminUsername,
                    passwordEncoder.encode(adminPassword), // senha nunca salva em texto puro
                    adminName,
                    adminRole
            );
            userRepository.save(admin);
            System.out.println("[DataInitializer] Usuário admin criado: " + adminUsername + " — altere a senha após o primeiro login.");
            return admin;
        });
    }

    // Cria a role se não existir, retorna a existente ou a recém-criada.
    private Role ensureRole(String name) {
        return roleRepository.findByName(name)
                .orElseGet(() -> {
                    Role role = new Role();
                    role.setName(name);
                    return roleRepository.save(role);
                });
    }

 */
}
