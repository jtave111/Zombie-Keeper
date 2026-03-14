package com.manager.Zombie_Keeper.ui.manager;

import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.stage.Stage;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class SceneManager {

    private Stage primaryStage; 
    private final ApplicationContext springContext;
    private static final double APP_WIDTH = 1600;
    private static final double APP_HEIGHT = 900;

    private final Map<ViewEnum, Node> viewCache = new HashMap<>();

    public SceneManager(ApplicationContext springContext) {
        this.springContext = springContext;
    }

    public void setPrimaryStage(Stage stage) {
        this.primaryStage = stage;
    }

    public Node loadPane(ViewEnum view) {
        
        if (viewCache.containsKey(view)) {
            return viewCache.get(view);
        }

        
        try {
            FXMLLoader loader = new FXMLLoader(
                getClass().getResource(view.getFxmlPath())
            );
            loader.setControllerFactory(springContext::getBean);
            Node rootNode = loader.load();
            
            
            viewCache.put(view, rootNode);
            
            return rootNode;
            
        } catch (IOException e) {
            System.err.println("[-] Failed to load pane: " + view.getFxmlPath());
            e.printStackTrace();
            return new Label("Error loading: " + view.name());
        }
    }

    public void changeScreen(ViewEnum view) {
       try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource(view.getFxmlPath()));
            
            loader.setControllerFactory(springContext::getBean); 
            
            Parent root = loader.load();
            Scene scene = new Scene(root, APP_WIDTH, APP_HEIGHT);
            
         primaryStage.setScene(scene);
            
           primaryStage.setResizable(false); 
            
          
            primaryStage.setTitle("Zombie Keeper C2 - " + view.getTitle());
            primaryStage.centerOnScreen();
            primaryStage.show();
            
        } catch (IOException e) {
            System.err.println("[-] Failed to load screen: " + view.name() + " -> " + view.getFxmlPath());
            e.printStackTrace();
        }
    }
}