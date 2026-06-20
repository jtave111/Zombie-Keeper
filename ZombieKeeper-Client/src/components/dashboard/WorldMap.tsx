import { useEffect, useRef, useState } from 'react';
import { AgentGeo } from '@/lib/models/agents/agentModel';
import { C2Info } from '@/lib/client/api';

const STATUS_COLOR: Record<string, string> = {
  ONLINE: '#e05c6e', IDLE: '#d48b55', LOST: '#555',
};

interface Props { geoAgents: AgentGeo[]; c2: C2Info | null; }

export default function WorldMap({ geoAgents, c2 }: Props) {
  const mapRef  = useRef<HTMLDivElement>(null);
  const mapInst = useRef<any>(null);
  const [zoom,  setZoom]  = useState(3);
  const [hover, setHover] = useState<AgentGeo | null>(null);

  useEffect(() => {
    if (!mapRef.current || mapInst.current) return;
    let destroyed = false;

    import('leaflet').then(L => {
      if (destroyed || !mapRef.current) return;

      const map = L.map(mapRef.current, {
        center: [25, 15],
        zoom: 2,
        minZoom: 2,
        maxZoom: 14,
        zoomControl: false,
        attributionControl: false,
        worldCopyJump: false,
        maxBounds: L.latLngBounds(L.latLng(-75, -210), L.latLng(85, 210)),
        maxBoundsViscosity: 1.0,
      });
      mapInst.current = map;

      map.on('zoomend', () => setZoom(map.getZoom()));

      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd', maxZoom: 19, noWrap: true,
        bounds: L.latLngBounds(L.latLng(-90, -180), L.latLng(90, 180)),
      }).addTo(map);

      /* Labels layer (shown at zoom ≥ 5) */
      const labelsLayer = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_only_labels/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd', maxZoom: 19, noWrap: true, opacity: 0.45,
      });
      map.on('zoomend', () => {
        if (map.getZoom() >= 5 && !map.hasLayer(labelsLayer)) labelsLayer.addTo(map);
        if (map.getZoom() <  5 &&  map.hasLayer(labelsLayer)) map.removeLayer(labelsLayer);
      });

      L.control.zoom({ position: 'bottomright' }).addTo(map);

      /* C2 marker */
      if (c2) {
        const icon = L.divIcon({
          html: `<div style="position:relative;width:44px;height:44px;">
            <div style="position:absolute;inset:-10px;border-radius:50%;background:rgba(224,92,110,0.12);animation:zkP 1.8s ease-out infinite;"></div>
            <div style="position:absolute;inset:-4px;border-radius:50%;border:1px solid rgba(224,92,110,0.3);animation:zkP 1.8s 0.5s ease-out infinite;"></div>
            <div style="position:absolute;inset:0;border-radius:50%;background:radial-gradient(circle,#ff8899 0%,#e05c6e 55%,#c03050 100%);box-shadow:0 0 22px rgba(224,92,110,0.7),0 0 6px #e05c6e;"></div>
            <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:8px;height:8px;border-radius:50%;background:#fff;"></div>
            <div style="position:absolute;top:-22px;left:50%;transform:translateX(-50%);white-space:nowrap;color:#e05c6e;font-family:'Courier New';font-size:8px;letter-spacing:1.5px;text-shadow:0 0 8px #e05c6e;pointer-events:none;">C2</div>
          </div>`,
          className:'', iconSize:[44,44], iconAnchor:[22,22],
        });
        const loc = `${c2.city ?? ''}${c2.city && c2.country ? ', ' : ''}${c2.country ?? ''}` || 'Unknown';
        const ip  = c2.publicIp ? `${c2.publicIp}:${c2.listenPort ?? 4444}` : `0.0.0.0:${c2.listenPort ?? 4444}`;
        L.marker([c2.lat, c2.lng], { icon })
          .addTo(map)
          .bindPopup(mkPopup({
            title: `C2 SERVER${c2.name ? ' — ' + c2.name : ''}`,
            rows: [['Location', loc], ['Listen', ip], ['Status', 'ONLINE']],
            col: '#e05c6e',
          }), { className:'zkpop', maxWidth:240 });
      }

      /* Agent markers */
      geoAgents.forEach((agent, idx) => {
        const col = STATUS_COLOR[agent.status];
        const on  = agent.status === 'ONLINE';

        const icon = L.divIcon({
          html: `<div style="position:relative;width:32px;height:32px;">
            ${on ? `
              <div style="position:absolute;inset:-12px;border-radius:50%;background:${col}18;animation:zkP 2.4s ease-out infinite;"></div>
              <div style="position:absolute;inset:-5px;border-radius:50%;background:${col}12;animation:zkP 2.4s 0.8s ease-out infinite;"></div>` : ''}
            <div style="position:absolute;inset:0;border-radius:50%;
              background:radial-gradient(circle,${col} 0%,${col}cc 50%,transparent 100%);
              border:1.5px solid ${col};
              box-shadow:${on ? `0 0 14px ${col}66,0 0 4px ${col}` : 'none'};"></div>
            <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:5px;height:5px;border-radius:50%;background:#fff;opacity:0.9;"></div>
            <div style="position:absolute;top:50%;left:-8px;width:5px;height:0.8px;background:${col};opacity:0.4;transform:translateY(-50%);"></div>
            <div style="position:absolute;top:50%;right:-8px;width:5px;height:0.8px;background:${col};opacity:0.4;transform:translateY(-50%);"></div>
            <div style="position:absolute;left:50%;top:-8px;height:5px;width:0.8px;background:${col};opacity:0.4;transform:translateX(-50%);"></div>
            <div style="position:absolute;left:50%;bottom:-8px;height:5px;width:0.8px;background:${col};opacity:0.4;transform:translateX(-50%);"></div>
          </div>`,
          className:'', iconSize:[32,32], iconAnchor:[16,16], popupAnchor:[0,-20],
        });

        L.marker([agent.lat, agent.lng], { icon })
          .addTo(map)
          .bindPopup(mkPopup({
            title: `[${agent.status}] ${agent.id}`,
            rows: [
              ['IP',       agent.ip],
              ['Location', `${agent.city}, ${agent.country}`],
              ['Hostname', agent.hostname || '—'],
              ['Priv',     agent.priv || '—'],
            ],
            col,
          }), { className:'zkpop', maxWidth:250 });

        /* Arc from agent to C2 */
        if (on && c2) {
          const pts: [number,number][] = [];
          const N = 60;
          for (let i = 0; i <= N; i++) {
            const t = i / N;
            pts.push([
              agent.lat + (c2.lat - agent.lat) * t - Math.sin(t * Math.PI) * 10,
              agent.lng + (c2.lng - agent.lng) * t,
            ]);
          }
          L.polyline(pts, { color:'#e05c6e', weight:0.8, opacity:0.18, dashArray:'5 9', smoothFactor:2 }).addTo(map);

          /* Traveling dot */
          const dot = L.circleMarker([agent.lat, agent.lng], {
            radius:2.5, color:'#e05c6e', fillColor:'#ffaabb', fillOpacity:0.9, opacity:0.9, weight:0,
          }).addTo(map);

          let step = 0; const total = N + 25;
          const tick = () => {
            if (destroyed) return;
            step = (step + 1) % total;
            if (step < N) {
              dot.setLatLng(pts[step]);
              const o = 0.9 - (step / N) * 0.6;
              dot.setStyle({ opacity:o, fillOpacity:o });
            } else {
              dot.setLatLng([agent.lat, agent.lng]);
              dot.setStyle({ opacity:0, fillOpacity:0 });
            }
            setTimeout(tick, 38 + idx * 10);
          };
          setTimeout(tick, idx * 700);
        }
      });

      map.setZoom(5, { animate:false });
      setTimeout(() => map.flyTo([30, 15], 3, { animate:true, duration:2.0, easeLinearity:0.25 }), 400);
    });

    return () => {
      destroyed = true;
      if (mapInst.current) { mapInst.current.remove(); mapInst.current = null; }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function mkPopup({ title, rows, col }: { title: string; rows: [string, string][]; col: string }) {
    const rowsHtml = rows.map(([k, v]) =>
      `<div style="display:flex;gap:0;padding:2px 0;border-bottom:1px solid #1e1e1e;">
        <span style="color:#5a5a5a;min-width:72px;font-size:10px;">${k}</span>
        <span style="color:#a8a8a8;font-size:11px;word-break:break-all;">${v}</span>
      </div>`
    ).join('');
    return `<div style="background:#1a1a1a;border:1px solid ${col};padding:10px 12px;font-family:'Courier New';min-width:195px;box-shadow:0 0 16px ${col}33;">
      <div style="color:${col};font-weight:700;font-size:12px;margin-bottom:8px;letter-spacing:0.5px;">▸ ${title}</div>
      ${rowsHtml}
    </div>`;
  }

  return (
    <div style={{ position:'relative', width:'100%', height:'100%', background:'#060a0e', overflow:'hidden' }}>
      <style>{`
        @import url('https://unpkg.com/leaflet@1.9.4/dist/leaflet.css');
        @keyframes zkP { 0%{transform:scale(1);opacity:.6} 100%{transform:scale(2.6);opacity:0} }
        .zkpop .leaflet-popup-content-wrapper{background:transparent!important;border:none!important;box-shadow:none!important;padding:0!important;border-radius:0!important;}
        .zkpop .leaflet-popup-content{margin:0!important;}
        .zkpop .leaflet-popup-tip-container{display:none!important;}
        .zkpop .leaflet-popup-close-button{color:#555!important;right:4px!important;top:4px!important;font-size:14px!important;}
        .leaflet-control-zoom{border:none!important;box-shadow:none!important;}
        .leaflet-control-zoom a{background:#111!important;border:1px solid #222!important;color:#555!important;font-family:'Courier New'!important;border-radius:0!important;}
        .leaflet-control-zoom a:hover{background:#1a0008!important;color:#e05c6e!important;border-color:#e05c6e!important;}
        .leaflet-tile{filter:brightness(0.58) contrast(1.08) saturate(0.7)!important;}
        .leaflet-container{background:#060a0e!important;}
        .leaflet-control-attribution{display:none!important;}
      `}</style>

      {/* Header bar */}
      <div style={{ position:'absolute', top:0, left:0, right:0, zIndex:1000, height:24, background:'rgba(6,10,14,0.96)', borderBottom:'1px solid #0d1824', display:'flex', alignItems:'center', padding:'0 12px', gap:14, fontFamily:'Courier New', fontSize:10 }}>
        <span style={{ color:'#2a3e50', letterSpacing:2, textTransform:'uppercase' }}>ZK // Global Agent Telemetry</span>
        <span style={{ color:'#0e1e2a' }}>|</span>
        {(['ONLINE','IDLE','LOST'] as const).map(s => (
          <span key={s} style={{ display:'flex', alignItems:'center', gap:5 }}>
            <span style={{ width:5, height:5, borderRadius:'50%', background:STATUS_COLOR[s], display:'inline-block', boxShadow:`0 0 4px ${STATUS_COLOR[s]}` }} />
            <span style={{ color:STATUS_COLOR[s] }}>{geoAgents.filter(a => a.status === s).length} {s}</span>
          </span>
        ))}
        <span style={{ marginLeft:'auto', color:'#1a2a38', fontSize:9 }}>Scroll=zoom · Click=info · Drag=pan</span>
        <span style={{ color:'#1a2a38', fontSize:9 }}>Z:{zoom}</span>
      </div>

      <div ref={mapRef} style={{ position:'absolute', top:24, left:0, right:0, bottom:0 }} />

      {/* Vignette overlay */}
      <div style={{ position:'absolute', inset:0, pointerEvents:'none', zIndex:500, background:'radial-gradient(ellipse 80% 80% at 50% 55%,transparent 40%,rgba(3,6,12,0.5) 100%)' }} />

      {/* Agent list (bottom-left) */}
      <div style={{ position:'absolute', bottom:12, left:12, zIndex:1000, background:'rgba(6,10,14,0.94)', border:'1px solid #0d1824', padding:'7px 10px', fontFamily:'Courier New', fontSize:10, maxWidth:220 }}>
        {!geoAgents.length && (
          <div style={{ color:'#3a4a58' }}>[*] No agent geo data</div>
        )}
        {geoAgents.map(a => (
          <div key={a.id} style={{ display:'flex', gap:8, alignItems:'center', marginBottom:2 }}>
            <span style={{ width:5, height:5, borderRadius:'50%', background:STATUS_COLOR[a.status], flexShrink:0, boxShadow: a.status==='ONLINE' ? `0 0 4px ${STATUS_COLOR[a.status]}` : 'none' }} />
            <span style={{ color:STATUS_COLOR[a.status], minWidth:58, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{a.id}</span>
            <span style={{ color:'#4a5a68', flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{a.city}</span>
          </div>
        ))}
      </div>

      {/* Hover tooltip (when agent hovered) */}
      {hover && (
        <div style={{ position:'absolute', top:36, right:12, zIndex:1000, background:'rgba(6,10,14,0.96)', border:`1px solid ${STATUS_COLOR[hover.status]}`, padding:'8px 10px', fontFamily:'Courier New', fontSize:10 }}>
          <div style={{ color:STATUS_COLOR[hover.status], fontWeight:700, marginBottom:5 }}>▸ {hover.id}</div>
          <div style={{ color:'#5a7888' }}>IP: <span style={{ color:'#5bb8d4' }}>{hover.ip}</span></div>
          <div style={{ color:'#5a7888' }}>Loc: <span style={{ color:'#888' }}>{hover.city}, {hover.country}</span></div>
        </div>
      )}
    </div>
  );
}
