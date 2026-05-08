'use client';
import { useEffect, useRef } from 'react';
import { AgentGeo } from '@/lib/data';
import { C2Info } from '@/lib/api';

const STATUS_COLOR: Record<string, string> = {
  ONLINE: '#e05c6e', IDLE: '#d48b55', LOST: '#555',
};

interface Props { geoAgents: AgentGeo[]; c2: C2Info | null; }

export default function WorldMap({ geoAgents, c2 }: Props) {
  const mapRef  = useRef<HTMLDivElement>(null);
  const mapInst = useRef<any>(null);

  useEffect(() => {
    if (!mapRef.current || mapInst.current) return;
    let destroyed = false;

    import('leaflet').then(L => {
      if (destroyed || !mapRef.current) return;

      const southWest = L.latLng(-75, -210);
      const northEast = L.latLng(85,  210);

      const map = L.map(mapRef.current, {
        center: [25, 15],
        zoom: 2,
        minZoom: 2,
        maxZoom: 8,
        zoomControl: false,
        attributionControl: false,
        worldCopyJump: false,
        maxBounds: L.latLngBounds(southWest, northEast),
        maxBoundsViscosity: 1.0,
      });
      mapInst.current = map;

      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd',
        maxZoom: 19,
        noWrap: true,
        bounds: L.latLngBounds(L.latLng(-90, -180), L.latLng(90, 180)),
      }).addTo(map);

      L.control.zoom({ position: 'bottomright' }).addTo(map);

      // C2 server marker — only rendered when backend info is available
      if (c2) {
        const c2Icon = L.divIcon({
          html: `<div style="position:relative;width:44px;height:44px;">
            <div style="position:absolute;inset:-10px;border-radius:50%;background:rgba(224,92,110,0.15);animation:zkP 1.8s ease-out infinite;"></div>
            <div style="position:absolute;inset:-4px;border-radius:50%;border:1px solid rgba(224,92,110,0.35);animation:zkP 1.8s 0.5s ease-out infinite;"></div>
            <div style="position:absolute;inset:0;border-radius:50%;background:radial-gradient(circle,#ff8899 0%,#e05c6e 55%,#c03050 100%);box-shadow:0 0 22px rgba(224,92,110,0.7),0 0 6px #e05c6e;"></div>
            <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:8px;height:8px;border-radius:50%;background:#fff;"></div>
            <div style="position:absolute;top:-22px;left:50%;transform:translateX(-50%);white-space:nowrap;color:#e05c6e;font-family:'Courier New';font-size:8px;letter-spacing:1.5px;text-shadow:0 0 8px #e05c6e;pointer-events:none;">C2 SERVER</div>
          </div>`,
          className:'', iconSize:[44,44], iconAnchor:[22,22],
        });

        const c2Loc = `${c2.city ?? ''}${c2.city && c2.country ? ', ' : ''}${c2.country ?? ''}` || 'Unknown';
        const c2Ip  = c2.publicIp ? `${c2.publicIp}:${c2.listenPort ?? 4444}/tcp` : `0.0.0.0:${c2.listenPort ?? 4444}/tcp`;

        L.marker([c2.lat, c2.lng], { icon: c2Icon })
          .addTo(map)
          .bindPopup(popup(`C2 SERVER${c2.name ? ' — ' + c2.name : ''}`, c2Loc, c2Ip, null, '#e05c6e'), { className:'zkpop', maxWidth:220 });
      }

      // Agent markers + arcs
      geoAgents.forEach((agent, idx) => {
        const col = STATUS_COLOR[agent.status];
        const on  = agent.status === 'ONLINE';

        const icon = L.divIcon({
          html: `<div style="position:relative;width:34px;height:34px;">
            ${on ? `
              <div style="position:absolute;inset:-12px;border-radius:50%;background:${col}22;animation:zkP 2.2s ease-out infinite;"></div>
              <div style="position:absolute;inset:-5px;border-radius:50%;background:${col}18;animation:zkP 2.2s 0.7s ease-out infinite;"></div>` : ''}
            <div style="position:absolute;inset:0;border-radius:50%;
              background:radial-gradient(circle,${col} 0%,${col}cc 50%,transparent 100%);
              border:1.5px solid ${col};
              box-shadow:${on ? `0 0 18px ${col}77,0 0 5px ${col}` : 'none'};"></div>
            <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
              width:5px;height:5px;border-radius:50%;background:#fff;opacity:0.9;"></div>
            <div style="position:absolute;top:50%;left:-9px;width:6px;height:0.8px;background:${col};opacity:0.5;transform:translateY(-50%);"></div>
            <div style="position:absolute;top:50%;right:-9px;width:6px;height:0.8px;background:${col};opacity:0.5;transform:translateY(-50%);"></div>
            <div style="position:absolute;left:50%;top:-9px;height:6px;width:0.8px;background:${col};opacity:0.5;transform:translateX(-50%);"></div>
            <div style="position:absolute;left:50%;bottom:-9px;height:6px;width:0.8px;background:${col};opacity:0.5;transform:translateX(-50%);"></div>
          </div>`,
          className:'', iconSize:[34,34], iconAnchor:[17,17], popupAnchor:[0,-20],
        });

        L.marker([agent.lat, agent.lng], { icon })
          .addTo(map)
          .bindPopup(popup(`[${agent.status}] ${agent.id}`, `${agent.city}, ${agent.country}`, agent.ip, agent.status, col), { className:'zkpop', maxWidth:230 });

        if (on && c2) {
          const pts: [number,number][] = [];
          const N = 60;
          for (let i = 0; i <= N; i++) {
            const t = i / N;
            const lat = agent.lat + (c2.lat - agent.lat) * t - Math.sin(t * Math.PI) * 12;
            const lng = agent.lng + (c2.lng - agent.lng) * t;
            pts.push([lat, lng]);
          }

          L.polyline(pts, { color:'#e05c6e', weight:0.9, opacity:0.22, dashArray:'6 10', smoothFactor:2 }).addTo(map);

          const dot = L.circleMarker([agent.lat, agent.lng], {
            radius:3, color:'#e05c6e', fillColor:'#ffaabb',
            fillOpacity:0.9, opacity:0.9, weight:0,
          }).addTo(map);

          let step = 0; const total = N + 20;
          const tick = () => {
            if (destroyed) return;
            step = (step + 1) % total;
            if (step < N) {
              dot.setLatLng(pts[step]);
              const o = 0.9 - (step / N) * 0.55;
              dot.setStyle({ opacity:o, fillOpacity:o });
            } else {
              dot.setLatLng([agent.lat, agent.lng]);
              dot.setStyle({ opacity:0, fillOpacity:0 });
            }
            setTimeout(tick, 40 + idx * 12);
          };
          setTimeout(tick, idx * 800);
        }
      });

      map.setZoom(5, { animate: false });
      setTimeout(() => {
        map.flyTo([30, 15], 3, { animate: true, duration: 2.0, easeLinearity: 0.25 });
      }, 400);
    });

    return () => {
      destroyed = true;
      if (mapInst.current) { mapInst.current.remove(); mapInst.current = null; }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function popup(id: string, loc: string, ip: string, status: string | null, col: string) {
    return `<div style="background:#0d0d0d;border:1px solid ${col};padding:11px 14px;
      font-family:'Courier New';font-size:11px;min-width:185px;
      box-shadow:0 0 18px ${col}44;">
      <div style="color:${col};font-weight:700;font-size:13px;margin-bottom:8px;">▸ ${id}</div>
      ${status ? `<div style="color:#333;margin-bottom:3px;">Status: <span style="color:${col}">${status}</span></div>`:''}
      <div style="color:#333;margin-bottom:3px;">IP: <span style="color:#5bb8d4">${ip}</span></div>
      <div style="color:#333;">Location: <span style="color:#555">${loc}</span></div>
    </div>`;
  }

  return (
    <div style={{ position:'relative', width:'100%', height:'100%', background:'#060a0e', overflow:'hidden' }}>
      <style>{`
        @import url('https://unpkg.com/leaflet@1.9.4/dist/leaflet.css');
        @keyframes zkP { 0%{transform:scale(1);opacity:.65} 100%{transform:scale(2.8);opacity:0} }
        .zkpop .leaflet-popup-content-wrapper{background:transparent!important;border:none!important;box-shadow:none!important;padding:0!important;border-radius:0!important;}
        .zkpop .leaflet-popup-content{margin:0!important;}
        .zkpop .leaflet-popup-tip-container{display:none!important;}
        .zkpop .leaflet-popup-close-button{color:#555!important;right:5px!important;top:5px!important;font-size:14px!important;}
        .leaflet-control-zoom a{background:#0d0d0d!important;border:1px solid #1e1e1e!important;color:#555!important;font-family:'Courier New'!important;}
        .leaflet-control-zoom a:hover{background:#1a0000!important;color:#e05c6e!important;border-color:#e05c6e!important;}
        .leaflet-bar{border:none!important;box-shadow:none!important;}
        .leaflet-tile{filter:brightness(0.62) contrast(1.05)!important;}
        .leaflet-container{background:#060a0e!important;}
        .leaflet-control-attribution{display:none!important;}
      `}</style>

      {/* Header */}
      <div style={{ position:'absolute',top:0,left:0,right:0,zIndex:1000,height:26,
        background:'rgba(6,10,14,0.97)',borderBottom:'1px solid #0d1a24',
        display:'flex',alignItems:'center',padding:'0 14px',gap:16,fontFamily:'Courier New',fontSize:10 }}>
        <span style={{ color:'#1a3448',letterSpacing:2,textTransform:'uppercase' }}>ZK // Global Agent Telemetry</span>
        <span style={{ color:'#081018' }}>|</span>
        {(['ONLINE','IDLE','LOST'] as const).map(s => (
          <span key={s} style={{ display:'flex',alignItems:'center',gap:5 }}>
            <span style={{ width:5,height:5,borderRadius:'50%',background:STATUS_COLOR[s],display:'inline-block',boxShadow:`0 0 4px ${STATUS_COLOR[s]}` }}/>
            <span style={{ color:STATUS_COLOR[s] }}>{geoAgents.filter(a=>a.status===s).length} {s}</span>
          </span>
        ))}
        <span style={{ marginLeft:'auto',color:'#0e1a24',fontSize:9 }}>Scroll=zoom · Click=info · Drag=pan</span>
      </div>

      <div ref={mapRef} style={{ position:'absolute',top:26,left:0,right:0,bottom:0 }}/>

      {/* Vignette */}
      <div style={{ position:'absolute',inset:0,pointerEvents:'none',zIndex:500,
        background:'radial-gradient(ellipse 80% 80% at 50% 55%,transparent 45%,rgba(3,6,12,0.55) 100%)' }}/>

      {/* Agent list overlay */}
      {geoAgents.length > 0 && (
        <div style={{ position:'absolute',bottom:14,left:14,zIndex:1000,
          background:'rgba(5,8,14,0.93)',border:'1px solid #0d1a24',padding:'8px 12px',fontFamily:'Courier New',fontSize:10 }}>
          {geoAgents.map(a => (
            <div key={a.id} style={{ display:'flex',gap:10,alignItems:'center',marginBottom:3 }}>
              <span style={{ width:5,height:5,borderRadius:'50%',background:STATUS_COLOR[a.status],flexShrink:0 }}/>
              <span style={{ color:STATUS_COLOR[a.status],minWidth:55 }}>{a.id}</span>
              <span style={{ color:'#1a2a38' }}>{a.city}</span>
            </div>
          ))}
        </div>
      )}

      {geoAgents.length === 0 && (
        <div style={{ position:'absolute',bottom:14,left:14,zIndex:1000,
          background:'rgba(5,8,14,0.93)',border:'1px solid #0d1a24',padding:'8px 12px',fontFamily:'Courier New',fontSize:10,color:'#1a2a38' }}>
          [*] No agent geo data available
        </div>
      )}
    </div>
  );
}
