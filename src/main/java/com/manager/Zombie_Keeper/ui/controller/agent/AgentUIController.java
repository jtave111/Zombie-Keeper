package com.manager.Zombie_Keeper.ui.controller.agent;

import com.manager.Zombie_Keeper.model.entity.agent.Agent;
import com.manager.Zombie_Keeper.repository.agent.AgentRepository;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.concurrent.CompletableFuture;

@Component
public class AgentUIController {

    private static final Logger logger = LoggerFactory.getLogger(AgentUIController.class);

    @FXML private TableView<Agent> botnetOverviewTable;
    
    
    @FXML private TableColumn<Agent, Long> colPublicId;
    @FXML private TableColumn<Agent, String> colHostname;
    @FXML private TableColumn<Agent, String> colIpv4;
    
    @FXML private TableColumn<Agent, String> colOs;
    @FXML private TableColumn<Agent, String> colArchitecture;
    @FXML private TableColumn<Agent, String> colCurrentUser;
    @FXML private TableColumn<Agent, Boolean> colIsElevated;
    
    @FXML private TableColumn<Agent, String> colStatus;
    @FXML private TableColumn<Agent, LocalDateTime> colLastSeen;

    @FXML private TableColumn<Agent, String> colMacAddress;
    @FXML private TableColumn<Agent, String> colCountry;
    @FXML private TableColumn<Agent, String> colVersion;
    @FXML private TableColumn<Agent, Integer> colPid;

    @Autowired
    private AgentRepository agentRepository;

    @FXML
    public void initialize() {

        if (colPublicId != null) colPublicId.setCellValueFactory(new PropertyValueFactory<>("publicId"));
        if (colHostname != null) colHostname.setCellValueFactory(new PropertyValueFactory<>("hostname"));
        if (colIpv4 != null) colIpv4.setCellValueFactory(new PropertyValueFactory<>("ipv4"));
        
        if (colOs != null) colOs.setCellValueFactory(new PropertyValueFactory<>("os")); 
        if (colArchitecture != null) colArchitecture.setCellValueFactory(new PropertyValueFactory<>("architecture"));
        if (colCurrentUser != null) colCurrentUser.setCellValueFactory(new PropertyValueFactory<>("currentUser"));
        if (colIsElevated != null) colIsElevated.setCellValueFactory(new PropertyValueFactory<>("isElevated"));
        
        if (colStatus != null) colStatus.setCellValueFactory(new PropertyValueFactory<>("status"));
        if (colLastSeen != null) colLastSeen.setCellValueFactory(new PropertyValueFactory<>("lastSeen"));

        if (colMacAddress != null) colMacAddress.setCellValueFactory(new PropertyValueFactory<>("macAddress"));
        if (colCountry != null) colCountry.setCellValueFactory(new PropertyValueFactory<>("country"));
        if (colVersion != null) colVersion.setCellValueFactory(new PropertyValueFactory<>("version"));
        if (colPid != null) colPid.setCellValueFactory(new PropertyValueFactory<>("pid"));
        
        refreshTable();
    }

    @FXML
    public void refreshTable() {
        logger.debug("Solicitando atualização da lista de agentes ao banco de dados.");
        
        CompletableFuture.supplyAsync(() -> agentRepository.findAll())
            .thenAccept(agentsList -> {
                ObservableList<Agent> agents = FXCollections.observableArrayList(agentsList);
                Platform.runLater(() -> {
                    botnetOverviewTable.setItems(agents);
                    logger.info("Tabela atualizada com sucesso. Total de agentes: {}", agentsList.size());
                });
            })
            .exceptionally(ex -> {
                
                logger.error("Falha ao buscar os agentes no banco de dados.", ex);
                return null;
            });
    }

    @FXML
    public void deleteAgent() {
        Agent selectedAgent = botnetOverviewTable.getSelectionModel().getSelectedItem();
        
        if (selectedAgent != null) {
            logger.info("Iniciando exclusão do agente ID: {}", selectedAgent.getPublicId());
            
            CompletableFuture.runAsync(() -> agentRepository.delete(selectedAgent))
                .thenRun(() -> {
                    logger.info("Agente ID: {} excluído com sucesso.", selectedAgent.getPublicId());
                    Platform.runLater(this::refreshTable);
                })
                .exceptionally(ex -> {
                    logger.error("Falha ao deletar o agente ID: {}", selectedAgent.getPublicId(), ex);
                    return null;
                });
        } else {
            logger.warn("Tentativa de excluir agente, mas nenhum foi selecionado na tabela.");
        }
    }
    
    @FXML
    public void interactWithAgent() {
        Agent selectedAgent = botnetOverviewTable.getSelectionModel().getSelectedItem();
        
        if (selectedAgent != null) {
            logger.info("Iniciando terminal interativo (shell) com o Agente ID: {}", selectedAgent.getPublicId());
            // TODO: Lógica para abrir a view do terminal
        } else {
            logger.warn("Nenhum agente selecionado para interação.");
        }
    }
}