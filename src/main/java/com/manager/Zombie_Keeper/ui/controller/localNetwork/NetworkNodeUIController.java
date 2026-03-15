package com.manager.Zombie_Keeper.ui.controller.localNetwork;

import com.manager.Zombie_Keeper.model.entity.localNetwork.NetworkNode;
// import com.manager.Zombie_Keeper.service.localNetwork.NetworkNodeService; 
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.cell.PropertyValueFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;

@Component
public class NetworkNodeUIController {

    private static final Logger logger = LoggerFactory.getLogger(NetworkNodeUIController.class);

   @FXML private TableView<NetworkNode> nodesTable;
    @FXML private TableColumn<NetworkNode, String> colIpv4; 
    @FXML private TableColumn<NetworkNode, String> colMacAddress;
    @FXML private TableColumn<NetworkNode, String> colOs;
    @FXML private TableColumn<NetworkNode, String> colStatus;
    @FXML private TextArea nodeDetailsArea;
    @FXML private Button btnScanPorts;
    @FXML private Button btnDeployAgent;

  
    @FXML
    public void initialize() {
        logger.info("NULL");

        
        if (colIpv4 != null) colIpv4.setCellValueFactory(new PropertyValueFactory<>("ipv4"));
        if (colMacAddress != null) colMacAddress.setCellValueFactory(new PropertyValueFactory<>("macAddress"));
        if (colOs != null) colOs.setCellValueFactory(new PropertyValueFactory<>("os"));
        if (colStatus != null) colStatus.setCellValueFactory(new PropertyValueFactory<>("status"));

        btnScanPorts.setDisable(true);
        btnDeployAgent.setDisable(true);

        nodesTable.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
            if (newValue != null) {
                showNodeDetails(newValue);
                btnScanPorts.setDisable(false);
                btnDeployAgent.setDisable(false);
            } else {
                nodeDetailsArea.clear();
                btnScanPorts.setDisable(true);
                btnDeployAgent.setDisable(true);
            }
        });

        refreshTable();
    }

    @FXML
    public void refreshTable() {
        logger.debug("NULL");
        /*
        CompletableFuture.supplyAsync(() -> nodeService.getAllNodes())
            .thenAccept(nodesList -> {
                ObservableList<NetworkNode> nodes = FXCollections.observableArrayList(nodesList);
                Platform.runLater(() -> nodesTable.setItems(nodes));
            })
            .exceptionally(ex -> {
                logger.error("Falha ao buscar os Network Nodes.", ex);
                return null;
            });
        */
    }

    private void showNodeDetails(NetworkNode node) {
        StringBuilder sb = new StringBuilder();
        sb.append("--- ALVO SELECIONADO ---\n");
        sb.append("IP: ").append(node.getIpv4()).append("\n"); 
        sb.append("MAC: ").append(node.getMacAddress()).append("\n");
        sb.append("OS Detectado: ").append(node.getOs() != null ? node.getOs() : "Desconhecido").append("\n");
        
        Platform.runLater(() -> nodeDetailsArea.setText(sb.toString()));
    }

    @FXML
    public void actionScanPorts() {
        NetworkNode target = nodesTable.getSelectionModel().getSelectedItem();
        if (target != null) {
            logger.info("NULL: {}", target.getIpv4()); 
            nodeDetailsArea.appendText("\n NULL" + target.getIpv4() + "...\n"); 
        }
    }

    @FXML
    public void actionDeployAgent() {
        NetworkNode target = nodesTable.getSelectionModel().getSelectedItem();
        if (target != null) {
            logger.warn("NULL: {}", target.getIpv4()); 
            nodeDetailsArea.appendText("\nNULL " + target.getIpv4() + "...\n"); 
        }
    }
}