function updateClock() {
            const now = new Date();
            const timeStr = now.toISOString().split('T')[1].split('.')[0] + " UTC";
            const clockEl = document.getElementById('clock');
            if(clockEl) clockEl.textContent = timeStr;
        }
        setInterval(updateClock, 1000);


const agentsBodyTable = document.getElementById("agents-body");


const endpoint = '/c2-server/agents';


async function loadAgents() {
    
    const response = await fetch(endpoint);

    const data =  await response.json();


    try{
        const response = await fetch(endpoint, {
            credentials: 'same-origin'
        });

        if(!response.ok){

            console.error(`Erro HTTP: ${response.status}`);

            return;
        }

        data.forEach(agent => {
            
            const tr = document.createElement("tr");
            tr.className = "border-b border-red-900/20 hover:bg-red-900/10 transition-colors";

            tr.innerHTML = ` 
                <td class="p-4 font-mono text-red-500">${agent.hostname || 'Unknown'}</td>
                <td class="p-4 text-gray-400 font-mono text-xs">${agent.osRaw || agent.os || 'Unknown'}</td>
                <td class="p-4 font-mono text-red-400">${agent.ipAddress || agent.ip || '0.0.0.0'}</td>
                <td class="p-4 text-right font-mono text-xs text-red-800">${agent.lastSeen || 'Never'}</td>    
            `;

            agentsBodyTable.appendChild(tr);

            agentsBodyTable.appendChild(tr);
        });


    }catch(error){

         console.error("Endpoint fatal error", error);
    }

}


loadAgents();
updateClock();
