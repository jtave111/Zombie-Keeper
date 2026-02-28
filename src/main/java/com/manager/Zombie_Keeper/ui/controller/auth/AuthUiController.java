package com.manager.Zombie_Keeper.ui.controller.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.manager.Zombie_Keeper.model.entity.auth.User;
import com.manager.Zombie_Keeper.repository.auth.UserRepository;
import com.manager.Zombie_Keeper.ui.manager.SceneManager; 
import com.manager.Zombie_Keeper.ui.manager.ViewEnum; 

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import java.util.Optional;

@Component
public class AuthUiController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SceneManager sceneManager; 

    @FXML private TextField txtUsername;
    @FXML private PasswordField txtPassword;
    @FXML private Button btnConnect;
    
   
    @FXML private VBox terminalOutput; 

    @FXML
    public void performLogin() {
        String username = txtUsername.getText();
        String password = txtPassword.getText();

        if (username.isEmpty() || password.isEmpty()) {
            addTerminalLog("ERRO: INFORME OPERADOR E CHAVE.", true);
            return;
        }

        txtUsername.setDisable(true);
        txtPassword.setDisable(true);
        btnConnect.setDisable(true);
        btnConnect.setText("A ESTABELECER LIGAÇÃO...");
        btnConnect.getStyleClass().add("btn-disabled");

        terminalOutput.getChildren().clear(); 

        
        new Thread(() -> {
            try {
                String[] sequence = {
                    "INITIATING HANDSHAKE PROTOCOL...",
                    "RESOLVING ONION ROUTING PATHS...",
                    "PINGING PRIMARY ZOMBIE NODES...",
                    "ENCRYPTING PAYLOAD (AES-256-GCM)...",
                    "VERIFYING OPERATOR CREDENTIALS..."
                };

                for (String log : sequence) {
                    Platform.runLater(() -> addTerminalLog(log, false));
                    Thread.sleep((long) (600 + Math.random() * 400)); 
                }

                Optional<User> userOptional = userRepository.findByUsername(username);

                Platform.runLater(() -> {
                    if (userOptional.isPresent() && passwordEncoder.matches(password, userOptional.get().getPassword())) {
                        
                        addTerminalLog("ACCESS GRANTED. WELCOME TO THE SWARM.", false);
                        
                        new Thread(() -> {
                            try { Thread.sleep(1000); } catch (Exception ignored) {}
                            Platform.runLater(() -> {
                                Authentication auth = new UsernamePasswordAuthenticationToken(userOptional.get(), null, userOptional.get().getAuthorities());
                                SecurityContextHolder.getContext().setAuthentication(auth);
                                sceneManager.changeScreen(ViewEnum.DASHBOARD);
                            });
                        }).start();

                    } else {
                        addTerminalLog("ERROR: INVALID CREDENTIALS. CONNECTION REFUSED.", true);
                        resetForm("ACCESS DENIED");
                    }
                });

            } catch (Exception e) {
                Platform.runLater(() -> resetForm("ERRO DE SISTEMA"));
            }
        }).start();
    }

    // Método auxiliar para injetar labels no painel do Terminal
    private void addTerminalLog(String text, boolean isError) {
        Label logLine = new Label("> " + text);
        logLine.getStyleClass().add("terminal-text");
        if (isError) {
            logLine.setStyle("-fx-text-fill: #f43f5e;"); 
        } else if (text.contains("CONCEDIDO")) {
            logLine.setStyle("-fx-text-fill: #10b981; -fx-font-weight: bold;"); 
        }
        terminalOutput.getChildren().add(logLine);
    }

  
    private void resetForm(String buttonText) {
        txtUsername.setDisable(false);
        txtPassword.setDisable(false);
        btnConnect.setDisable(false);
        btnConnect.setText("⚠ " + buttonText);
        btnConnect.getStyleClass().remove("btn-disabled");
    }
}