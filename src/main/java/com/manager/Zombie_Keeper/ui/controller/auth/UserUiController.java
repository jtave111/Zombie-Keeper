package com.manager.Zombie_Keeper.ui.controller.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.manager.Zombie_Keeper.model.entity.auth.User;
import com.manager.Zombie_Keeper.repository.auth.UserRepository;


import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;

@Component
public class UserUiController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder encoder;

    @FXML private TextField txtUsername;
    @FXML private PasswordField txtPassword;
    @FXML private Label lblStatusMessage;

    @FXML
    public void createUser() {
        String username = txtUsername.getText();
        String plainPass = txtPassword.getText();

        if (username.isEmpty() || plainPass.isEmpty()) {
            lblStatusMessage.setText("Error: Fields cannot be empty.");
            return;
        }

        User user = new User();
        user.setUsername(username);
        
        String passEncoder = encoder.encode(plainPass);
        user.setPassword(passEncoder);
        
        userRepository.save(user);

        lblStatusMessage.setText("User " + username + " created successfully!");
        
        txtUsername.clear();
        txtPassword.clear();
    }

    public User getActualUser() {
       
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (auth != null && auth.getPrincipal() instanceof User) {
            return (User) auth.getPrincipal();
        }
        return null;
    }
}