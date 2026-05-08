package com.manager.Zombie_Keeper.model.enums.agent;

public enum LocationSource {
    GPS,      // coletado pelo dispositivo — mais preciso
    WIFI,     // triangulação WiFi — médio
    IP,       // fallback por IP — menos preciso, nível de cidade
    UNKNOWN,
    DEVICE
}
