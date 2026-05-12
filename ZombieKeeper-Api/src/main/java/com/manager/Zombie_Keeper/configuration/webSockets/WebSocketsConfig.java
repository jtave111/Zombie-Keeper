package com.manager.Zombie_Keeper.configuration.webSockets;

import com.manager.Zombie_Keeper.configuration.security.JwtHandshakeInterceptor;
import com.manager.Zombie_Keeper.handler.webSockets.TerminalWebSocketsHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

@Configuration
@EnableWebSocket
public class WebSocketsConfig implements WebSocketConfigurer {

    private final TerminalWebSocketsHandler terminalHandler;
    private final JwtHandshakeInterceptor jwtHandshakeInterceptor;

    public WebSocketsConfig(TerminalWebSocketsHandler terminalHandler,
                            JwtHandshakeInterceptor jwtHandshakeInterceptor) {
        this.terminalHandler = terminalHandler;
        this.jwtHandshakeInterceptor = jwtHandshakeInterceptor;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(terminalHandler, "/term")
                .addInterceptors(jwtHandshakeInterceptor)
                .setAllowedOrigins("*");
    }
}
