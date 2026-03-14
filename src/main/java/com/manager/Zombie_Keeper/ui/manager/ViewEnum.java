package com.manager.Zombie_Keeper.ui.manager;

public enum ViewEnum {

    LOGIN("/fxml/login.fxml", "Operator Authentication"),
    MAIN_LAYOUT("/fxml/main_dashboard.fxml", "Main Dashboard"), 

    //Refactor path for package
    
    HOME("/fxml/home.fxml", "Overview"),       
    AGENTS("/fxml/agents.fxml", "Agents"),     
    NETWORK_SESSION("/fxml/network_session.fxml", "Network Session"),  
    SHELL("/fxml/shell.fxml", "Reverse Shell"),
    PAYLOADS("/fxml/payloads.fxml", "Payload Generator"),
    LOGS("/fxml/logs.fxml", "Session Logs"),
    SETTINGS("/fxml/settings.fxml", "System Settings"); 

    private final String fxmlPath;
    private final String title;

    ViewEnum(String fxmlPath, String title) {
        this.fxmlPath = fxmlPath;
        this.title = title;
    }

    public String getFxmlPath() { return fxmlPath; }
    public String getTitle()    { return title; }
}