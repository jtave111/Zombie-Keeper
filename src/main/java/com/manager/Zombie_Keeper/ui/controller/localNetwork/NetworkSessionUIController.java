package com.manager.Zombie_Keeper.ui.controller.localNetwork;

import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkNode;
import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkSession;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class NetworkSessionUIController {

    private static final Logger logger = LoggerFactory.getLogger(NetworkSessionUIController.class);

    
    @FXML private ListView<NetworkSession> sessionListView; 
    @FXML private TableView<NetworkNode> nodeTableView;
    @FXML private TableColumn<NetworkNode, String> colNodeIpv4; 
    @FXML private TableColumn<NetworkNode, String> colNodeMac;
    @FXML private TableColumn<NetworkNode, String> colNodeOs;
    @FXML private TextArea nodeDetailsArea;

    
    @FXML private ToggleButton tabMap;
    @FXML private ToggleButton tabScanner;
    @FXML private HBox viewTopology;
    @FXML private VBox viewScannerManager;
    @FXML private Button btnRunScan;
    @FXML private Label netInfo;

 
    @FXML
    public void initialize() {
        logger.info("Inicializando o painel Tático de Network Sessions...");

        
        if (colNodeIpv4 != null) colNodeIpv4.setCellValueFactory(new PropertyValueFactory<>("ipv4"));
        if (colNodeMac != null)  colNodeMac.setCellValueFactory(new PropertyValueFactory<>("macAddress"));
        if (colNodeOs != null)   colNodeOs.setCellValueFactory(new PropertyValueFactory<>("os"));

       
        if (sessionListView != null) {
            sessionListView.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
                if (newValue != null) {
                    logger.debug("Session slected: {}", newValue.getId());
                    loadNodesForSession(newValue);
                }
            });
        }

        if (nodeTableView != null) {
            nodeTableView.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
                if (newValue != null) {
                    showNodeDetails(newValue);
                }
            });
        }

        
        switchTab();
        loadAllSessions();
    }

    
    @FXML
    public void switchTab() {
        if (tabMap != null && tabScanner != null) {
            if (tabMap.isSelected()) {
                viewTopology.setVisible(true);
                viewTopology.setManaged(true);
                
                viewScannerManager.setVisible(false);
                viewScannerManager.setManaged(false);
            } else if (tabScanner.isSelected()) {
                viewScannerManager.setVisible(true);
                viewScannerManager.setManaged(true);
                
                viewTopology.setVisible(false);
                viewTopology.setManaged(false);
            }
        }
    }

    
    @FXML
    public void runFullScan() {
        if (btnRunScan != null) {
            btnRunScan.setText("⟳ NULL");
            btnRunScan.setDisable(true);
        }
        logger.info("NULL");
        
       
    }

 
    private void loadAllSessions() {
        logger.info("NULL");

    }

    private void loadNodesForSession(NetworkSession session) {
        logger.info("NULL");
    }

    private void showNodeDetails(NetworkNode node) {
        if (nodeDetailsArea == null) return;
        
        StringBuilder details = new StringBuilder();
        details.append("IP Address: ").append(node.getIpv4()).append("\n");
        details.append("MAC Address: ").append(node.getMacAddress()).append("\n");
        
        Platform.runLater(() -> nodeDetailsArea.setText(details.toString()));
    }
}