package com.manager.Zombie_Keeper.ui.controller.agent;

import com.manager.Zombie_Keeper.model.entity.agent.Loot;
import com.manager.Zombie_Keeper.repository.agent.LootRepository;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.concurrent.CompletableFuture;

@Component
public class LootUIController {

    @FXML private TableView<Loot> lootTable;

   
    @FXML private TableColumn<Loot, String> colType; 
    @FXML private TableColumn<Loot, String> colContent; 
    @FXML private TableColumn<Loot, LocalDateTime> colCapturedAt; 
    
    
    @FXML private TableColumn<Loot, String> colAgentId; 

    @Autowired
    private LootRepository lootRepository;

    @FXML
    public void initialize() {
        if (colType != null) colType.setCellValueFactory(new PropertyValueFactory<>("type"));
        if (colContent != null) colContent.setCellValueFactory(new PropertyValueFactory<>("content"));
        if (colCapturedAt != null) colCapturedAt.setCellValueFactory(new PropertyValueFactory<>("capturedAt"));
        
        
        if (colAgentId != null) colAgentId.setCellValueFactory(new PropertyValueFactory<>("agentIdentifier")); 
        
        refreshTable();
    }

    @FXML
    public void refreshTable() {
        
        CompletableFuture.supplyAsync(() -> lootRepository.findAll())
            .thenAccept(lootList -> {
                ObservableList<Loot> loots = FXCollections.observableArrayList(lootList);
                Platform.runLater(() -> lootTable.setItems(loots));
            })
            .exceptionally(ex -> {
                System.err.println("Failed to fetch loots: " + ex.getMessage());
                return null;
            });
    }

    @FXML
    public void deleteLoot() {
        Loot selectedLoot = lootTable.getSelectionModel().getSelectedItem();
        
        if (selectedLoot != null) {
            CompletableFuture.runAsync(() -> lootRepository.delete(selectedLoot))
                .thenRun(() -> Platform.runLater(this::refreshTable))
                .exceptionally(ex -> {
                    System.err.println("Failed to delete loot: " + ex.getMessage());
                    return null;
                });
        }
    }

    @FXML
    public void viewLootDetails() {
        Loot selectedLoot = lootTable.getSelectionModel().getSelectedItem();
        
        if (selectedLoot != null) {
            System.out.println("Opening details for Loot Type: " + selectedLoot.getType());
            // TODO: Open a new JavaFX modal or text area showing the full content of the loot.
        
        } else {
            System.out.println("No loot selected for viewing.");
        }
    }
}