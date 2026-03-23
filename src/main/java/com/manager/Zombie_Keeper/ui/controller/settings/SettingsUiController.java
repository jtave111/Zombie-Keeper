package com.manager.Zombie_Keeper.ui.controller.settings;

import java.net.URL;
import java.util.List;
import java.util.ResourceBundle;

import org.springframework.stereotype.Component;

import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleButton;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;

@Component
public class SettingsUiController implements Initializable {

    // ── Nav items ─────────────────────────────────────────────────────
    @FXML private HBox navGeneral;
    @FXML private HBox navServer;
    @FXML private HBox navUsers;
    @FXML private HBox navDatabase;
    @FXML private HBox navNetwork;
    @FXML private HBox navLogging;
    @FXML private HBox navAbout;
    @FXML private HBox navDanger;

    // ── Content stack ─────────────────────────────────────────────────
    @FXML private StackPane contentStack;

    // ── Views ─────────────────────────────────────────────────────────
    @FXML private ScrollPane viewGeneral;
    @FXML private ScrollPane viewServer;
    @FXML private ScrollPane viewUsers;
    @FXML private ScrollPane viewDatabase;
    @FXML private ScrollPane viewNetwork;
    @FXML private ScrollPane viewLogging;
    @FXML private ScrollPane viewAbout;
    @FXML private ScrollPane viewDanger;

    // ── General ───────────────────────────────────────────────────────
    @FXML private Label        lblCurrentUser;
    @FXML private TextField    txtFrameworkName;
    @FXML private TextField    txtVersion;
    @FXML private ToggleButton togClock;
    @FXML private ToggleButton togNotifications;
    @FXML private ComboBox<String> cmbSessionTimeout;
    @FXML private ToggleButton togAutoLock;

    // ── C2 Server ─────────────────────────────────────────────────────
    @FXML private StackPane    c2StatusDot;
    @FXML private Label        lblC2Status;
    @FXML private TextField    txtListenerPort;
    @FXML private TextField    txtBindAddress;
    @FXML private ComboBox<String> cmbProtocol;
    @FXML private ComboBox<String> cmbHeartbeat;
    @FXML private ComboBox<String> cmbAgentTimeout;
    @FXML private ToggleButton togReconnect;

    // ── Users & RBAC ──────────────────────────────────────────────────
    @FXML private TableView<Object>    userTable;
    @FXML private TableColumn<Object, String> colUsername;
    @FXML private TableColumn<Object, String> colName;
    @FXML private TableColumn<Object, String> colRole;
    @FXML private TableColumn<Object, String> colLastLogin;
    @FXML private TableColumn<Object, String> colUserStatus;
    @FXML private TableColumn<Object, String> colActions;
    @FXML private ToggleButton rbacViewAgents;
    @FXML private ToggleButton rbacShell;
    @FXML private ToggleButton rbacScanner;
    @FXML private ToggleButton rbacUserMgmt;

    // ── Database ──────────────────────────────────────────────────────
    @FXML private StackPane    dbStatusDot;
    @FXML private Label        lblDbStatus;
    @FXML private TextField    txtDbHost;
    @FXML private TextField    txtDbPort;
    @FXML private TextField    txtDbName;
    @FXML private TextField    txtDbUser;
    @FXML private ComboBox<String> cmbLogRetention;
    @FXML private ToggleButton togBackup;

    // ── Network ───────────────────────────────────────────────────────
    @FXML private TextField    txtDefaultSubnet;
    @FXML private ComboBox<String> cmbInterface;
    @FXML private ComboBox<String> cmbScanProfile;
    @FXML private TextField    txtNmapPath;
    @FXML private ToggleButton togScanOnBoot;
    @FXML private ComboBox<String> cmbScanInterval;

    // ── Logging ───────────────────────────────────────────────────────
    @FXML private ComboBox<String> cmbLogLevel;
    @FXML private ToggleButton togLogAuth;
    @FXML private ToggleButton togLogShell;
    @FXML private ToggleButton togLogScan;
    @FXML private TextField    txtLogPath;
    @FXML private ComboBox<String> cmbLogRotation;

    // ═════════════════════════════════════════════════════════════════
    //  INIT
    // ═════════════════════════════════════════════════════════════════

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        populateCombos();
        setupToggleLabels();
    }

    private void populateCombos() {
        cmbSessionTimeout.getItems().addAll("30 minutos", "1 hora", "4 horas", "Nunca");
        cmbSessionTimeout.getSelectionModel().select(1);

        cmbProtocol.getItems().addAll("TCP", "TCP/TLS", "HTTP", "HTTPS");
        cmbProtocol.getSelectionModel().selectFirst();

        cmbHeartbeat.getItems().addAll("5s", "10s", "30s", "60s");
        cmbHeartbeat.getSelectionModel().select(1);

        cmbAgentTimeout.getItems().addAll("30s", "60s", "2min", "5min");
        cmbAgentTimeout.getSelectionModel().select(1);

        cmbLogRetention.getItems().addAll("7 dias", "30 dias", "90 dias", "Nunca");
        cmbLogRetention.getSelectionModel().select(1);

        cmbInterface.getItems().addAll("eth0", "wlan0", "tun0");
        cmbInterface.getSelectionModel().selectFirst();

        cmbScanProfile.getItems().addAll("STEALTH", "STANDARD", "AGGRESSIVE");
        cmbScanProfile.getSelectionModel().selectFirst();

        cmbScanInterval.getItems().addAll("30s", "1min", "5min", "15min");
        cmbScanInterval.getSelectionModel().select(1);

        cmbLogLevel.getItems().addAll("DEBUG", "INFO", "WARN", "ERROR");
        cmbLogLevel.getSelectionModel().select(1);

        cmbLogRotation.getItems().addAll("Diário", "Semanal", "Por tamanho (10MB)");
        cmbLogRotation.getSelectionModel().selectFirst();
    }

    private void setupToggleLabels() {
        // Sync toggle text with selected state
        List.of(togClock, togNotifications, togAutoLock, togReconnect,
                togBackup, togScanOnBoot, togLogAuth, togLogShell, togLogScan)
            .forEach(t -> t.selectedProperty().addListener((obs, o, n) ->
                t.setText(n ? "ON" : "OFF")));
    }

    // ═════════════════════════════════════════════════════════════════
    //  NAVIGATION
    // ═════════════════════════════════════════════════════════════════

    private final String ACTIVE = "s-nav-active";

    private void showView(Node view, HBox nav) {
        List.of(viewGeneral, viewServer, viewUsers, viewDatabase,
                viewNetwork, viewLogging, viewAbout, viewDanger)
            .forEach(v -> { v.setVisible(false); v.setManaged(false); });
        List.of(navGeneral, navServer, navUsers, navDatabase,
                navNetwork, navLogging, navAbout, navDanger)
            .forEach(n -> n.getStyleClass().remove(ACTIVE));

        view.setVisible(true);
        ((javafx.scene.layout.Region) view).setManaged(true);
        nav.getStyleClass().add(ACTIVE);
    }

    @FXML private void showGeneral()  { showView(viewGeneral,  navGeneral); }
    @FXML private void showServer()   { showView(viewServer,   navServer); }
    @FXML private void showUsers()    { showView(viewUsers,    navUsers); }
    @FXML private void showDatabase() { showView(viewDatabase, navDatabase); }
    @FXML private void showNetwork()  { showView(viewNetwork,  navNetwork); }
    @FXML private void showLogging()  { showView(viewLogging,  navLogging); }
    @FXML private void showAbout()    { showView(viewAbout,    navAbout); }
    @FXML private void showDanger()   { showView(viewDanger,   navDanger); }

    // ═════════════════════════════════════════════════════════════════
    //  SAVE HANDLERS
    // ═════════════════════════════════════════════════════════════════

    @FXML private void onCancelGeneral() { /* restaura valores originais */ }

    @FXML
    private void onSaveGeneral() {
        // TODO: salvar no banco / application.properties via service
        System.out.println("Framework name: " + txtFrameworkName.getText());
        System.out.println("Clock: " + togClock.isSelected());
    }

    @FXML
    private void onSaveServer() {
        // TODO: reiniciar listener com nova config
        System.out.println("Port: " + txtListenerPort.getText());
        System.out.println("Bind: " + txtBindAddress.getText());
    }

    @FXML private void onNewUser() { /* abrir dialog de criação de usuário */ }

    @FXML
    private void onTestDb() {
        // TODO: testar conexão JDBC
        System.out.println("Testing DB connection...");
    }

    @FXML private void onSaveDb()      { System.out.println("Saving DB config..."); }
    @FXML private void onSaveNetwork() { System.out.println("Saving network config..."); }
    @FXML private void onSaveLogging() { System.out.println("Saving logging config..."); }

    // ═════════════════════════════════════════════════════════════════
    //  DANGER ZONE HANDLERS
    // ═════════════════════════════════════════════════════════════════

    @FXML
    private void onDisconnectAll() {
        // TODO: confirmar dialog → chamar AgentService.disconnectAll()
        System.out.println("Disconnecting all agents...");
    }

    @FXML
    private void onClearAgents() {
        // TODO: confirmar dialog → chamar AgentService.clearAll()
        System.out.println("Clearing agent table...");
    }

    @FXML
    private void onClearScans() {
        // TODO: confirmar dialog → chamar NetworkSessionService.clearAll()
        System.out.println("Clearing scan history...");
    }

    @FXML
    private void onRestartServer() {
        // TODO: confirmar dialog → chamar C2ServerService.restart()
        System.out.println("Restarting C2 server...");
    }

    @FXML
    private void onFactoryReset() {
        // TODO: dupla confirmação → reset completo
        System.out.println("Factory reset...");
    }
}