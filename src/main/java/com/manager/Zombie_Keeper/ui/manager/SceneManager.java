package com.manager.Zombie_Keeper.ui.manager;

import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class SceneManager {

    private Stage primaryStage; 
    private final ApplicationContext springContext;

    public SceneManager(ApplicationContext springContext) {
        this.springContext = springContext;
    }

    public void setPrimaryStage(Stage stage) {
        this.primaryStage = stage;
    }

   
    public void changeScreen(ViewEnum view) {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource(view.getFxmlPath()));
            
            // O Spring injeta as dependências nos Controllers do JavaFX
            loader.setControllerFactory(springContext::getBean); 
            
            Parent root = loader.load();
            Scene scene = new Scene(root);
            
           
            
            primaryStage.setTitle("Zombie Keeper C2 - " + view.getTitle());
            primaryStage.setScene(scene);
            primaryStage.centerOnScreen();
            primaryStage.show();
            
        } catch (IOException e) {
            System.err.println("Failed to load screen: " + view.name() + " -> " + view.getFxmlPath());
            e.printStackTrace();
        }
    }
}