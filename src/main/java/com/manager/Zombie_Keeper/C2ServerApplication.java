package com.manager.Zombie_Keeper;

import com.manager.Zombie_Keeper.ui.manager.SceneManager;
import com.manager.Zombie_Keeper.ui.manager.ViewEnum; // Import do Enum
import javafx.application.Application;
import javafx.stage.Stage;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
public class C2ServerApplication extends Application {

    private ConfigurableApplicationContext springContext;

    @Override
    public void init() throws Exception {
        springContext = SpringApplication.run(C2ServerApplication.class);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        SceneManager sceneManager = springContext.getBean(SceneManager.class);
        sceneManager.setPrimaryStage(primaryStage);
        
        // Fica muito mais limpo e imune a erros de digitação!
        sceneManager.changeScreen(ViewEnum.LOGIN); 
    }

    @Override
    public void stop() throws Exception {
        springContext.close(); 
    }

    public static void main(String[] args) {
        Application.launch(args);
    }
}