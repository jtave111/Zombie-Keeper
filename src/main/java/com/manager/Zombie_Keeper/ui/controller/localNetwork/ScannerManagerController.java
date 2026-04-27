package com.manager.Zombie_Keeper.ui.controller.localNetwork;

import java.net.URL;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ResourceBundle;

import org.springframework.stereotype.Component;

import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleButton;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.util.Duration;

@Component
public class ScannerManagerController implements Initializable {

    // ── Target ────────────────────────────────────────────────────────
    @FXML private TextField  txtTarget;
    @FXML private ComboBox<String> cmbSession;

    // ── Scan type (independent toggles) ──────────────────────────────
    @FXML private ToggleButton btnTcp;
    @FXML private ToggleButton btnUdp;
    @FXML private ToggleButton btnOs;
    @FXML private ToggleButton btnSvc;

    // ── Port scope ────────────────────────────────────────────────────
    @FXML private ToggleButton scopeCommon;
    @FXML private ToggleButton scopeFull;
    @FXML private ToggleButton scopeCustom;
    @FXML private VBox         customPortsBox;
    @FXML private TextField    txtCustomPorts;

    // ── Aggression ────────────────────────────────────────────────────
    @FXML private ToggleButton aggrStealth;
    @FXML private ToggleButton aggrStd;
    @FXML private ToggleButton aggrAggr;
    @FXML private Label        lblAggrDesc;

    // ── Automation ────────────────────────────────────────────────────
    @FXML private ToggleButton btnAutoToggle;
    @FXML private VBox         autoOptionsBox;
    @FXML private StackPane    autoDot;
    @FXML private Label        lblAutoStatus;

    // ── Launch ────────────────────────────────────────────────────────
    @FXML private Button btnLaunch;

    // ── Output bar ────────────────────────────────────────────────────
    @FXML private StackPane  phaseDot;
    @FXML private Label      lblPhase;
    @FXML private ProgressBar scanProgress;

    // ── Terminal ──────────────────────────────────────────────────────
    @FXML private javafx.scene.control.ScrollPane terminalScroll;
    @FXML private VBox terminalOutput;

    // ── Nodes panel ───────────────────────────────────────────────────
    @FXML private Label lblNodeCount;
    @FXML private VBox  nodeList;

    // ── Stats bar ─────────────────────────────────────────────────────
    @FXML private Label sHosts;
    @FXML private Label sPorts;
    @FXML private Label sVulns;
    @FXML private Label sAgents;
    @FXML private Label lblDuration;

    // ── State ─────────────────────────────────────────────────────────
    private boolean scanning   = false;
    private boolean autoActive = false;
    private Timeline autoTimeline;


    @Override
    public void initialize(URL url, ResourceBundle rb) {
        cmbSession.getItems().addAll("Corp-Local (eth0)", "Guest-WiFi (wlan0)", "VPN-Tunnel (tun0)");
        cmbSession.getSelectionModel().selectFirst();
        addLog("SYS", "tag-sys", "Scanner ready. Configure and launch.");
    }


    @FXML
    private void onScopeCustom() {
        boolean custom = scopeCustom.isSelected();
        customPortsBox.setVisible(custom);
        customPortsBox.setManaged(custom);
    }

    @FXML
    private void onAggrChange() {
        if (aggrStealth.isSelected())
            lblAggrDesc.setText("Lento · Menos detecção · SYN scan");
        else if (aggrStd.isSelected())
            lblAggrDesc.setText("Balanceado · Portas comuns · -sV");
        else if (aggrAggr.isSelected())
            lblAggrDesc.setText("Rápido · Todas as portas · -A");
    }

    @FXML
    private void onAutoToggle() {
        autoActive = btnAutoToggle.isSelected();
        btnAutoToggle.setText(autoActive ? "ON" : "OFF");
        autoDot.getStyleClass().remove("running");
        if (autoActive) {
            autoDot.getStyleClass().add("running");
            lblAutoStatus.setText("Automation: ACTIVE · next in 30s");
        } else {
            lblAutoStatus.setText("Automation: INACTIVE");
            if (autoTimeline != null) autoTimeline.stop();
        }
    }

    @FXML
    private void onLaunch() {
        if (scanning) return;
        startScan();
    }

    @FXML
    private void onClear() {
        terminalOutput.getChildren().clear();
        addLog("SYS", "tag-sys", "Terminal cleared.");
    }

    @FXML
    private void onExport() {
        addLog("SYS", "tag-sys", "Export: results.json — saved.");
    }


    private void startScan() {
        scanning = true;
        btnLaunch.setDisable(true);
        btnLaunch.setText("⟳  SCANNING...");
        nodeList.getChildren().clear();
        lblNodeCount.setText("0 hosts");
        sHosts.setText("0"); sPorts.setText("0");
        sVulns.setText("0"); sAgents.setText("0");
        scanProgress.setProgress(0);
        phaseDot.getStyleClass().add("active");

        String target = txtTarget.getText();
        long startMs  = System.currentTimeMillis();

        schedule(300,  () -> {
            lblPhase.setText("Phase 1 — Host Discovery");
            scanProgress.setProgress(0.05);
            addLog("SYS", "tag-sys", "Iniciando scan em " + target);
            addLog("SYS", "tag-sys", "TCP=" + btnTcp.isSelected() + " UDP=" + btnUdp.isSelected()
                + " Scope=" + getScope());
        });
        schedule(1400, () -> {
            scanProgress.setProgress(0.35);
            addLog("DISC", "tag-find", "192.168.1.1  — up (ttl=64)");
            addLog("DISC", "tag-find", "192.168.1.44 — up (ttl=128)");
            addLog("DISC", "tag-find", "192.168.1.88 — up (ttl=64)");
        });
        schedule(2800, () -> {
            lblPhase.setText("Phase 2 — Port Scan");
            scanProgress.setProgress(0.55);
            addLog("PORT", "tag-ok", "192.168.1.44 → 445/tcp  3389/tcp  135/tcp");
            addLog("PORT", "tag-ok", "192.168.1.88 → 22/tcp  8080/tcp");
            addLog("PORT", "tag-warn", "192.168.1.120 — no response");
        });
        schedule(4200, () -> {
            lblPhase.setText("Phase 3 — Service Detection");
            scanProgress.setProgress(0.80);
            addLog("SVC", "tag-sys", "192.168.1.44 · SMB → Windows 11");
            addLog("SVC", "tag-warn", "192.168.1.44 · 3306/MySQL → remote access exposed");
            addLog("AGNT", "tag-find", "ZK Agent detected @ 192.168.1.44");
        });
        schedule(5500, () -> {
            scanProgress.setProgress(1.0);
            double dur = (System.currentTimeMillis() - startMs) / 1000.0;
            lblPhase.setText("Complete");
            phaseDot.getStyleClass().remove("active");
            sHosts.setText("3"); sPorts.setText("7");
            sVulns.setText("2"); sAgents.setText("1");
            lblNodeCount.setText("3 hosts");
            lblDuration.setText(String.format("%.1fs", dur));
            addLog("OK", "tag-ok", "Scan completo · 3 hosts · 2 vulns · " + String.format("%.1fs", dur));
            btnLaunch.setDisable(false);
            btnLaunch.setText("▶  LAUNCH LOCAL SCAN");
            scanning = false;

        });
    }

    private void schedule(long ms, Runnable action) {
        Timeline tl = new Timeline(new KeyFrame(Duration.millis(ms),
            e -> action.run()));
        tl.play();
    }

    private String getScope() {
        if (scopeFull.isSelected())   return "Full 0-65535";
        if (scopeCustom.isSelected()) return "Custom: " + txtCustomPorts.getText();
        return "Common top-1000";
    }

    private void addLog(String tag, String tagCls, String msg) {
        String time = ZonedDateTime.now(ZoneOffset.UTC)
            .format(DateTimeFormatter.ofPattern("HH:mm:ss"));

        HBox row = new HBox(8);
        Label lTime = new Label(time); lTime.getStyleClass().add("tl-time");
        Label lTag  = new Label(tag);  lTag.getStyleClass().addAll("tl-tag", tagCls);
        Label lMsg  = new Label(msg);  lMsg.getStyleClass().add("tl-msg");

        row.getChildren().addAll(lTime, lTag, lMsg);
        terminalOutput.getChildren().add(row);

        terminalScroll.layout();
        terminalScroll.setVvalue(1.0);
    }

    //  NODE CARD BUILDER (chame com dados reais do NetworkNode)

    /*
    private VBox buildNodeCard(NetworkNode n) {
        VBox card = new VBox(4);
        card.getStyleClass().add("node-card");

        HBox top = new HBox(6);
        Label ip = new Label(n.getIpv4()); ip.getStyleClass().add("nc-ip");
        top.getChildren().add(ip);
        if (n.isAgent()) {
            Label badge = new Label("☣ AGENT"); badge.getStyleClass().addAll("badge","badge-agent");
            top.getChildren().add(badge);
        }

        Label mac = new Label(n.getMacAddress() + " · " + n.getVendor());
        mac.getStyleClass().add("nc-mac");

        Label os = new Label(n.getOs());
        os.getStyleClass().add("nc-os");

        HBox ports = new HBox(3);
        for (Port p : n.getOpenPorts()) {
            Label pt = new Label(p.getNumber() + "/" + p.getProtocol());
            pt.getStyleClass().addAll("port-tag", p.isRisk() ? "port-tag-risk" : "port-tag-open");
            ports.getChildren().add(pt);
        }

        StackPane vulnBg = new StackPane(); vulnBg.getStyleClass().add("vuln-bar");
        StackPane vulnFill = new StackPane();
        String vulnCls = n.getVulnerabilityScore() > 66 ? "vuln-high"
                       : n.getVulnerabilityScore() > 33 ? "vuln-medium" : "vuln-low";
        vulnFill.getStyleClass().add(vulnCls);
        // set width proportionally in controller after layout

        card.getChildren().addAll(top, mac, os, ports, vulnBg);
        return card;
    }
    */
}