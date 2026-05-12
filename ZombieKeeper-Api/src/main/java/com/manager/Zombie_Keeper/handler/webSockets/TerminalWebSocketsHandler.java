package com.manager.Zombie_Keeper.handler.webSockets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Component
public class TerminalWebSocketsHandler extends TextWebSocketHandler {

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private static final Logger logger = LoggerFactory.getLogger(TerminalWebSocketsHandler.class);

    private record ShellSession(Process process, OutputStream stdin, ExecutorService reader) {}

    private final Map<String, ShellSession> sessions = new ConcurrentHashMap<>();

    public void afterConnectionEstablished(WebSocketSession session) throws Exception{
        String operator = (String)session.getAttributes().get("operator");
        logger.info("Terminal aberto — operador: {}, sessão: {}", operator, session.getId());

        // o script aloca um PTY real do SO
        ProcessBuilder pb = new ProcessBuilder(
                "/bin/script", "-q", "-c", "/bin/bash -l", "/dev/null"
        );
        pb.environment().put("TERM", "xterm-256color");
        pb.environment().put("LANG", "en_US.UTF-8");
        pb.environment().put("HOME", System.getProperty("user.home"));
        pb.redirectErrorStream(true);

        Process process = pb.start();
        OutputStream stdin = process.getOutputStream();

        ExecutorService reader = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "terminal-reader-" + session.getId());
            t.setDaemon(true);
            return t;
        });

        sessions.put(session.getId(), new ShellSession(process, stdin, reader));

        InputStream stdout = process.getInputStream();
        reader.submit(() -> {
            byte[] buf = new byte[4096];
            int n;
            try {
                while ((n = stdout.read(buf)) != -1) {
                    if (!session.isOpen()) break;
                    String chunk = new String(buf, 0, n, StandardCharsets.UTF_8);
                    synchronized (session) {
                        session.sendMessage(new TextMessage(chunk));
                    }
                }
            } catch (IOException ignored) {
            } finally {
                closeQuietly(session);
            }
        });
    }
    @Override
    protected void handleTextMessage(WebSocketSession ws, TextMessage message) throws Exception {
        ShellSession s = sessions.get(ws.getId());
        if (s == null) return;

        String payload = message.getPayload();

        // resize: {"type":"resize","cols":120,"rows":30}
        if (payload.startsWith("{\"type\":\"resize\"")) {
            try {
                int cols = extractInt(payload, "cols");
                int rows = extractInt(payload, "rows");
                // envia stty ao bash para ajustar o tamanho do terminal
                String stty = "stty cols " + cols + " rows " + rows + "\n";
                s.stdin().write(stty.getBytes(StandardCharsets.UTF_8));
                s.stdin().flush();
            } catch (Exception ignored) {}
            return;
        }

        s.stdin().write(payload.getBytes(StandardCharsets.UTF_8));
        s.stdin().flush();
    }

    @Override
    public void afterConnectionClosed(WebSocketSession ws, CloseStatus status) {
        ShellSession s = sessions.remove(ws.getId());
        if (s == null) return;
        s.reader().shutdownNow();
        s.process().destroyForcibly();
        logger.info("Terminal fechado — sessão: {}, status: {}", ws.getId(), status);
    }

    private void closeQuietly(WebSocketSession ws) {
        try { if (ws.isOpen()) ws.close(); } catch (IOException ignored) {}
    }

    private int extractInt(String json, String key) {
        int i = json.indexOf("\"" + key + "\":");
        if (i < 0) throw new IllegalArgumentException("key not found: " + key);
        int start = json.indexOf(':', i) + 1;
        while (start < json.length() && json.charAt(start) == ' ') start++;
        int end = start;
        while (end < json.length() && Character.isDigit(json.charAt(end))) end++;
        return Integer.parseInt(json.substring(start, end));
    }

}
