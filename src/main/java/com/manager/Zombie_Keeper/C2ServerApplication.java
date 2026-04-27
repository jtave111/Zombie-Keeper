package com.manager.Zombie_Keeper;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication; // Import do Enum
import org.springframework.context.ConfigurableApplicationContext;

import com.manager.Zombie_Keeper.ui.manager.SceneManager;
import com.manager.Zombie_Keeper.ui.manager.ViewEnum;

import atlantafx.base.theme.PrimerDark;
import javafx.application.Application;
import javafx.stage.Stage;

@SpringBootApplication
public class C2ServerApplication extends Application {

    private ConfigurableApplicationContext springContext;

    @Override
    public void init() throws Exception {
        springContext = SpringApplication.run(C2ServerApplication.class);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        Application.setUserAgentStylesheet(new PrimerDark().getUserAgentStylesheet());
        SceneManager sceneManager = springContext.getBean(SceneManager.class);
        sceneManager.setPrimaryStage(primaryStage);
        
        
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