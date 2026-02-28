package com.manager.Zombie_Keeper.ui.manager;

public enum ViewEnum {
    
    
    LOGIN("/fxml/login.fxml", "Operator Authentication"),
    // TODO CREATE
    DASHBOARD("/fxml/home.fxml", "Main Dashboard"),
    SETTINGS("/fxml/settings.fxml", "System Settings"); 

    private final String fxmlPath;
    private final String title;

    ViewEnum(String fxmlPath, String title) {
        this.fxmlPath = fxmlPath;
        this.title = title;
    }

    public String getFxmlPath() {
        return fxmlPath;
    }

    public String getTitle() {
        return title;
    }
}