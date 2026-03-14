package com.manager.Zombie_Keeper.ui.controller.dashboard;

import java.net.URL;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.ResourceBundle;

import org.springframework.stereotype.Component;

import com.manager.Zombie_Keeper.ui.manager.SceneManager;
import com.manager.Zombie_Keeper.ui.manager.ViewEnum;

import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.util.Duration;

@Component
public class DashboardUiController implements Initializable {

    private final SceneManager sceneManager;

    public DashboardUiController(SceneManager sceneManager) {
        this.sceneManager = sceneManager;
    }

    // ── Topbar ────────────────────────────────────────────────────────
    @FXML private Label clockLabel;
    @FXML private Label bcCur;

    // ── O BURACO NEGRO ────────────────────────────────────────────────
    @FXML private StackPane contentStack;

    // ── Nav items (Menu Lateral) ──────────────────────────────────────
    @FXML private HBox navDashboard;
    @FXML private HBox navAgents;
    @FXML private HBox navNetwork;
    @FXML private HBox navShell;
    @FXML private HBox navPayloads;
    // Removido o navScanner fantasma daqui!
    @FXML private HBox navLogs;
    @FXML private HBox navSettings;

    // ═════════════════════════════════════════════════════════════════
    //  INIT
    // ═════════════════════════════════════════════════════════════════

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        startClock();
        showDashboard(); 
    }

    // ═════════════════════════════════════════════════════════════════
    //  CLOCK
    // ═════════════════════════════════════════════════════════════════

    private void startClock() {
        Timeline tl = new Timeline(new KeyFrame(Duration.seconds(1), e -> {
            String time = ZonedDateTime.now(ZoneOffset.UTC)
                .format(DateTimeFormatter.ofPattern("HH:mm:ss")) + " UTC";
            clockLabel.setText(time);
        }));
        tl.setCycleCount(Timeline.INDEFINITE);
        tl.play();
    }

    // ═════════════════════════════════════════════════════════════════
    //  INJEÇÃO DE TELAS (A MÁGICA DO CACHE)
    // ═════════════════════════════════════════════════════════════════

    private void injectView(ViewEnum viewEnum, String title, HBox activeNav) {
        Node view = sceneManager.loadPane(viewEnum);
        
        contentStack.getChildren().clear();
        contentStack.getChildren().add(view);
        
        bcCur.setText(title);
        setActiveNav(activeNav);
    }

    private void setActiveNav(HBox active) {
        // Removido o navScanner daqui e adicionada a trava anti-nulo
        List.of(navDashboard, navAgents, navNetwork, navShell,
                navPayloads, navLogs, navSettings)
            .forEach(n -> {
                if (n != null) { // Blindagem para não explodir
                    n.getStyleClass().remove("nav-active");
                }
            });
            
        if (active != null) {
            active.getStyleClass().add("nav-active");
        }
    }

    // ═════════════════════════════════════════════════════════════════
    //  BOTÕES DO MENU
    // ═════════════════════════════════════════════════════════════════

    @FXML private void showDashboard() { injectView(ViewEnum.HOME,     "Overview",    navDashboard); }
    @FXML private void showAgents()    { injectView(ViewEnum.AGENTS,   "Agents",      navAgents); }
    @FXML private void showNetwork()   { injectView(ViewEnum.NETWORK_SESSION,  "Network Session", navNetwork); }
    @FXML private void showShell()     { injectView(ViewEnum.SHELL,    "Shell",       navShell); }
    @FXML private void showPayloads()  { injectView(ViewEnum.PAYLOADS, "Payloads",    navPayloads); }
   
    @FXML private void showLogs()      { injectView(ViewEnum.LOGS,     "Logs",        navLogs); }
    @FXML private void showSettings()  { injectView(ViewEnum.SETTINGS, "Settings",    navSettings); } 
}