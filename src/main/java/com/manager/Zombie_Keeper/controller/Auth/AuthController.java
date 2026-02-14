package com.manager.Zombie_Keeper.controller.Auth;

import org.springframework.context.annotation.Lazy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.access.prepost.PreAuthorize; 
import org.springframework.web.bind.annotation.*;

import com.manager.Zombie_Keeper.dtos.auth.CreateAcRequest;
import com.manager.Zombie_Keeper.dtos.auth.LoginRequest;
import com.manager.Zombie_Keeper.model.entity.auth.Role;
import com.manager.Zombie_Keeper.model.entity.auth.User;
import com.manager.Zombie_Keeper.repository.auth.RoleRepository;
import com.manager.Zombie_Keeper.repository.auth.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    @Lazy
    private AuthenticationManager authenticationManager; 
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder encoder;
    
    @Autowired
    private RoleRepository roleRepository;
 

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid LoginRequest dto, HttpServletRequest request){
       
        try {
                
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(dto.getUsername(), dto.getPassword());
            
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

            HttpSession session = request.getSession(true);
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);      
            
            return ResponseEntity.ok("AUTHORIZED");

        } catch (AuthenticationException e) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User or Password invalid");
            
        }
    }

    @GetMapping("/get-session-id")
    public ResponseEntity<String> getHttpSessionId(HttpServletRequest request){
        
        HttpSession session = request.getSession();

        String sessionId = session.getId();

        System.out.println("Id da sessão " + sessionId);

        return ResponseEntity.ok(sessionId);
    }    
        /*
       Optional<User> userOptional = userRepository.findByUsername(dto.getUsername());
       
       System.out.println(">>> Requeste for user: " + dto.getUsername());

        if(userOptional.isPresent()){

            User user = userOptional.get();

            if(encoder.matches(dto.getPassword(), user.getPassword())){
                UserDetails userDetails = user;
                Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
                

                Authentication  authentication = new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
               // SecurityContextHolder.getContext().setAuthentication(authentication);
                
                //Registrar na sesão --- isso aqui garante o registro nas proximas requisições 
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                //O contexto e configurado com a autenticação 
                context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);

                //Salvando o contexto de segurança na sesão 
                HttpSession session = request.getSession(true);
                session.setAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    context
                );

                userLogged = userOptional.get();
       
            return ResponseEntity.ok("Authorized");
            }

        }
        */      
    


    @PostMapping("/register")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createAccount(@RequestBody @Valid CreateAcRequest dto){
        
        if (!dto.getPassword().equals(dto.getRepeetPassword())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Passwords do not match");
        }
        
        if(userRepository.findByUsername(dto.getUsername()).isPresent()){

            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
        }
        
        Role role = roleRepository.findByType(dto.getRole());
        if (role == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Role not found");
        }

        User  userRegister = new User();
        
        userRegister.setName(dto.getName());
        userRegister.setUsername(dto.getUsername());
        userRegister.setPassword(encoder.encode(dto.getPassword()));
        userRegister.setRole(role);

        userRepository.save(userRegister);
        return ResponseEntity.status(HttpStatus.CREATED).body(" User created");
                
        
    }


}
