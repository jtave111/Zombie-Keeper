package com.manager.Zombie_Keeper.controller.Auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.manager.Zombie_Keeper.model.entity.auth.User;
import com.manager.Zombie_Keeper.repository.auth.UserRepository;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder encoder;

    @PostMapping
    public ResponseEntity<User> creatUser(@RequestBody @Valid User user){

        String plainPass = user.getPassword();

        String passEncoder = encoder.encode(plainPass);

        user.setPassword(passEncoder);
        

        userRepository.save(user);

        return ResponseEntity.ok(user);
    }

    @GetMapping("/profile")
    public User getActualUser(Authentication auth){

        return (User) auth.getPrincipal();
    }

}
