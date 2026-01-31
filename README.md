<div align="center">

  <img src="https://capsule-render.vercel.app/api?type=waving&color=333333&height=220&section=header&text=Zombie%20Keeper&fontSize=80&fontColor=ff0000&animation=fadeIn&fontAlign=50" alt="Zombie Keeper Header" />

  # Zombie Keeper – Command & Control System
   
  **Dual-Purpose Command & Control: Infrastructure Monitoring & Offensive Operations**

  [![Command](https://img.shields.io/badge/Command-Spring%20Boot-green?logo=spring&style=for-the-badge)](https://spring.io/)
  [![Exploration](https://img.shields.io/badge/Exploration-C%2B%2B-00599C?logo=c%2B%2B&style=for-the-badge)](https://isocpp.org/)
  [![Comms](https://img.shields.io/badge/Comms-Raw%20Sockets-red?style=for-the-badge)](/)
 
</div>

---

---

### 💻⚙️ Mecanismos de Ação e Vetores de Operação

O Zombie Keeper atua como uma camada de abstração sobre a rede, permitindo **visibilidade granular** e **execução remota** através de três pilares críticos:

#### 1. Network Situational Awareness (Mapeamento e Visualização)
Antes de atacar ou defender, é preciso enxergar. O agente utiliza **Raw Sockets** para realizar varreduras passivas e ativas na sub-rede.
* **Mapeamento de Topologia:** Identificação automática de hosts vizinhos (ARP/ICMP) para desenhar o mapa da rede em tempo real.
* **Identificação de Superfície de Ataque:** Enumeração de portas e serviços rodando em máquinas adjacentes, facilitando a escolha de alvos para **Movimentação Lateral**.

* **🔵 Defensive Insight (Blue Team):** Utiliza a telemetria para **Observabilidade de Rede**. O sistema valida políticas de *Zero Trust* (verificando se segmentos isolados estão realmente isolados), detecta desvios de padrão (anomalias de tráfego) e expõe instantaneamente ativos ocultos (*Shadow IT*).
* **🔴 Offensive Intelligence (Red Team):** Transforma dados brutos em **Mapas de Vetores de Ataque**. O operador visualiza não apenas rotas, mas "Caminhos de Menor Resistência" para escalar privilégios, identificando serviços vulneráveis e ativos de alto valor (*Crown Jewels*) para planejar uma *Kill Chain* cirúrgica.


#### 2. Full-Spectrum Post-Exploitation (Controle e Exploração)
Uma vez estabelecida a conexão, o agente transforma a máquina em um nó de operação.
* **Command & Control (C2):** Canal criptografado e assíncrono para execução de Shell Remoto (RCE) e injeção de comandos de sistema.
* **Exfiltração de Dados:** Rotinas para extração de arquivos sensíveis e credenciais sem disparar alarmes volumétricos.
* **Persistência Tática:** O agente garante sua sobrevivência a reboots através de chaves de registro e *tasks* agendadas, mantendo o acesso ("Access Retention") mesmo após tentativas de remediação.

#### 3. Adversary Emulation (Testes de Segurança)
A plataforma permite simular comportamentos de *Threat Actors* reais para validar a eficácia das defesas (EDR/SIEM).
* Execução de cadeias de ataque controladas (ex: simular um ransomware ou um brute-force interno).
* Validação de segmentação de rede (testar se o Zumbi A consegue realmente alcançar o Servidor B).

---

## 🧠 Arquitetura de Controle
