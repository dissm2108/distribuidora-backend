// ════════════════════════════════════════════════════════════════
// SERVIDOR v5.0 — Distribuidora de panes y pasteles (Arequipa→Espinar)
// Alineado a los 42 bloques: SIN IA en pedidos (el dueño registra a mano),
// Twilio SOLO para alertas al dueño, Claude SOLO para el análisis del informe.
// Node 18+ · Express · Supabase · bcryptjs · jsonwebtoken
// ════════════════════════════════════════════════════════════════
const express=require("express"),cors=require("cors"),helmet=require("helmet");
const rateLimit=require("express-rate-limit");
const {createClient}=require("@supabase/supabase-js");
const bcrypt=require("bcryptjs"),jwt=require("jsonwebtoken"),cron=require("node-cron");

const OBLIG=["SUPABASE_URL","SUPABASE_SERVICE_KEY","JWT_SECRET","ADMIN_PASS"];
OBLIG.forEach(v=>{if(!process.env[v]){console.error("FALTA variable: "+v);process.exit(1);}});

const db=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_KEY);
/* 175 · 116 de 128 escrituras no revisaban si la base las rechazó. Sin tocar cada
   una, toda escritura con error queda registrada en los logs de Railway. */
(function(){const _from=db.from.bind(db);
  db.from=function(t){const q=_from(t);
    ["insert","update","upsert","delete"].forEach(m=>{const f=q[m];if(typeof f!=="function")return;
      q[m]=function(...a){const b=f.apply(q,a);
        try{const th=b.then.bind(b);b.then=(ok,ko)=>th(r=>{if(r&&r.error)console.error("[BD] "+m+" "+t+": "+r.error.message);return r;}).then(ok,ko);}catch(e){}
        return b;};});
    return q;};})();
// ── GPS ──
const GPS_PLAT=String(process.env.GPS_PLATFORM||"").toLowerCase().trim();
const GPS_MIN=Number(process.env.GPS_TIMEOUT_MIN)||15;   // minutos sin señal para dar por inactivo un camión
const SECRET=process.env.JWT_SECRET;
const ADMIN_TEL=process.env.ADMIN_TELEFONO||"";
// Opcionales: el sistema funciona sin ellos
let twilioC=null;if(process.env.TWILIO_ACCOUNT_SID&&process.env.TWILIO_AUTH_TOKEN){try{twilioC=require("twilio")(process.env.TWILIO_ACCOUNT_SID,process.env.TWILIO_AUTH_TOKEN);}catch(e){console.log("Twilio no disponible:",e.message);}}
let anthropic=null;if(process.env.ANTHROPIC_API_KEY){try{const A=require("@anthropic-ai/sdk");anthropic=new A({apiKey:process.env.ANTHROPIC_API_KEY});}catch(e){console.log("Anthropic no disponible:",e.message);}}
// ⬇️ Si Anthropic publica un modelo nuevo, cámbialo SOLO aquí:
const MODELO_IA="claude-sonnet-4-6";
/* 184 · pedidos: texto con Haiku 4.5 (barato); fotos de pedidos con Sonnet 5 */
const MODELO_IA_PEDIDOS="claude-haiku-4-5-20251001",MODELO_IA_FOTOS="claude-sonnet-5";

const app=express();
/* 175 · Express 4 no atrapa los errores de las rutas async: la petición quedaba
   colgada y el proceso podía caerse (Railway lo reinicia). Ahora responden 500 en JSON. */
["get","post","put","patch","delete","all"].forEach(m=>{
  const orig=app[m].bind(app);
  app[m]=function(ruta,...fns){
    if(m==="get"&&fns.length===0)return orig(ruta);
    return orig(ruta,...fns.map(f=>(typeof f==="function"&&f.length<4)?function(req,res,next){
      try{const r=f(req,res,next);
        if(r&&typeof r.catch==="function")r.catch(e=>{console.error("ERROR "+req.method+" "+req.path+":",e&&e.stack||e);
          if(!res.headersSent)res.status(500).json({ok:false,error:"Error interno del servidor: "+((e&&e.message)||e)});});
      }catch(e){next(e);}
    }:f));
  };
});
process.on("unhandledRejection",e=>console.error("unhandledRejection:",e&&e.stack||e));
// Sin ETag: Express respondía 304 "sin cambios" a la app, con cuerpo VACÍO.
// La app intentaba leer ese cuerpo, fallaba y se quedaba con el catálogo viejo.
app.set("etag",false);
app.use(express.json({limit:"2mb"})); // 2mb: fotos de fachada comprimidas
// helmet sin la política de contenido: la app y el panel llevan su código y estilos
// dentro del propio HTML, y el mapa carga desde OpenStreetMap. Con la política activa
// el navegador bloquea todo eso y la página queda muerta aunque cargue.
app.use(helmet({contentSecurityPolicy:false,crossOriginEmbedderPolicy:false,crossOriginResourcePolicy:false,originAgentCluster:false}));
const ORIG=(process.env.CORS_ORIGINS||"*").split(",").map(s=>s.trim()).filter(Boolean)
  .map(s=>s.replace(/\/+$/,"")).map(s=>/^https?:\/\//.test(s)?s:"https://"+s);
app.use(cors({origin:(o,cb)=>{
  if(!o||ORIG.includes("*")||!ORIG.length)return cb(null,true);
  cb(null,ORIG.includes(String(o).replace(/\/+$/,"")));
}}));
app.use(rateLimit({windowMs:15*60*1000,max:400}));
const NO_TOCAR=new Set(["pass","actual","nueva","clave","foto","imagen","texto"]);   /* 184 · imagen y texto se limpian en su ruta */
function sanea(o,prof){if(prof>7)return null;   /* 175 · antes 4: los puntos de las zonas llegaban vacíos */
 if(typeof o==="string")return limpia(o,300);
 if(Array.isArray(o))return o.slice(0,300).map(x=>sanea(x,prof+1));
 if(o&&typeof o==="object"){const r={};let n=0;for(const k of Object.keys(o)){if(++n>400)break;   /* 175 · antes 60: una carga con más de 60 productos se cortaba */const kk=String(k).slice(0,40);r[kk]=NO_TOCAR.has(kk)?o[k]:sanea(o[k],prof+1);}return r;}
 return o;}
app.use((req,res,next)=>{try{if(req.body&&typeof req.body==="object")req.body=sanea(req.body,0);}catch(e){}next();});
const authLimiter=rateLimit({windowMs:5*60*1000,max:25});
app.set("trust proxy",1); // IP real detrás de Railway (bloqueos y rate-limit correctos)
if((process.env.JWT_SECRET||"").length<24){console.error("JWT_SECRET demasiado corto: usa una frase de 24+ caracteres");process.exit(1);}
const {timingSafeEqual}=require("crypto");
const safeEq=(x,y)=>{x=Buffer.from(String(x));y=Buffer.from(String(y));return x.length===y.length&&timingSafeEqual(x,y);};
const USR_RE=/^[a-z0-9_]{3,20}$/;
const limpia=(s,max)=>String(s??"").replace(/[<>`]/g,"").replace(/[\u0000-\u001f\u007f]/g," ").trim().slice(0,max||300);
const num=(v,min,max,def)=>{if((v===undefined||v===null||v==="")&&def!==undefined)return def;v=Number(v);if(!isFinite(v))v=(def!==undefined?def:0);if(min!=null&&v<min)v=min;if(max!=null&&v>max)v=max;return v;};
const fotoOK=f=>typeof f==="string"&&/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(f)&&f.length<160000;
const CATS_BASE=["sm","bianka","panes","molde","especiales","chifones","tortas","queques"];
let CATS_OK=CATS_BASE.slice();   /* 175 · se completa con las categorías reales de la base */
async function refrescarCats(){try{const{data}=await db.from("categorias").select("id");if(data&&data.length)CATS_OK=[...new Set([...CATS_BASE,...data.map(c=>c.id)])];}catch(e){}}
setTimeout(refrescarCats,500);setInterval(refrescarCats,5*60*1000);
const catsOK=o=>{if(!o||typeof o!=="object")return null;const r={};CATS_OK.forEach(k=>{if(o[k]!=null)r[k]=num(o[k],0,99999)});return Object.keys(r).length?r:null;};
// Intentos fallidos por IP+usuario (además del rate limit)
const FALLOS=new Map();
const kIP=req=>String(req.ip||"?");
const falla=k=>{const f=FALLOS.get(k)||{n:0,ts:0};f.n++;f.ts=Date.now();FALLOS.set(k,f);};
const bloqueado=k=>{const f=FALLOS.get(k);return !!f&&f.n>=5&&(Date.now()-f.ts)<15*60*1000;};
const limpiaFallo=k=>FALLOS.delete(k);
setInterval(()=>{const lim=Date.now()-30*60*1000;for(const[k,f]of FALLOS)if(f.ts<lim)FALLOS.delete(k);},10*60*1000);

// ── helpers ──
// 175 · "hoy" es el día de Perú (UTC−5, sin horario de verano). Antes usaba UTC:
// a partir de las 19:00 de Lima el servidor ya creía que era mañana, y el informe
// de las 22:00 solo contaba las ventas de las últimas 3 horas.
const hoy=()=>new Date(Date.now()-5*3600000).toISOString().slice(0,10);
const fechaPE=v=>{try{return new Date(new Date(v).getTime()-5*3600000).toISOString().slice(0,10)}catch(e){return ""}};
const iniDia=d=>d+"T00:00:00-05:00", finDia=d=>d+"T23:59:59.999-05:00";
const horaPE=()=>new Date().toLocaleTimeString("es-PE",{hour:"2-digit",minute:"2-digit",timeZone:"America/Lima"});
/* 175 · tipo = el interruptor de Configuración → "Qué avisos me llegan por WhatsApp".
   Si el aviso no tiene su propio evento, también se deja en la Bandeja (antes, sin
   Twilio, esas alertas solo quedaban en los logs del servidor y nadie las veía). */
async function avisarAdmin(msg,tipo,bandeja){
  let p={};try{p=await getParams();}catch(e){}
  const tel=String((p.negocio&&p.negocio.tel)||ADMIN_TEL||"").replace(/\D/g,"");
  const activo=!tipo||!(p.avisos_cfg&&p.avisos_cfg[tipo]===false);
  if(bandeja){try{const l=String(msg).split("\n");await evento("alerta",l[0].slice(0,120),l.slice(1).join("\n")||l[0],"");}catch(e){}}
  if(!activo)return;
  if(twilioC&&tel){try{await twilioC.messages.create({from:process.env.TWILIO_WHATSAPP_FROM||"whatsapp:+14155238886",to:"whatsapp:+"+tel,body:msg});}catch(e){console.log("Twilio:",e.message);}}
  else console.log("[ALERTA ADMIN]",msg);
}
/* 175 · La deuda de cada tienda sale de su historial (cargos − abonos). Antes cada
   cambio leía el saldo, sumaba o restaba y lo escribía (dos cambios a la vez se
   pisaban), y los abonos NO quedaban en el historial: la base solo aceptaba "cargo"
   y "pago" y el servidor escribía "abono" (así se perdió el abono de TIENDA4). */
/* 182 · CADA ACREEDOR SU CUENTA. «dueno» = el dueño (lo que fían y cobran sus empleados);
   un independiente fía y cobra en su propia cuenta. tiendas.sa sigue siendo la deuda con el
   dueño (la que ve Créditos del panel); el total con todos se calcula del historial. */
const acreedorDe=m=>(m&&m.acreedor)||"dueno";
async function saldosTienda(tid){
  const{data}=await db.from("creditos_mov").select("tipo,monto,acreedor").eq("tienda_id",tid);
  const por={};
  (data||[]).forEach(m=>{const a=acreedorDe(m);por[a]=(por[a]||0)+(m.tipo==="cargo"?1:-1)*Number(m.monto||0);});
  let total=0;Object.keys(por).forEach(a=>{por[a]=Math.max(0,Math.round(por[a]*100)/100);total+=por[a];});
  return {por,total:Math.round(total*100)/100};
}
async function saldoHistorial(tid,acreedor){
  const s=await saldosTienda(tid);return s.por[acreedor||"dueno"]||0;
}
async function moverDeuda(tid,tipo,monto,detalle,por,acreedor){
  const A=acreedor||"dueno";
  monto=Math.round(num(monto,0,999999)*100)/100;
  if(!tid||!monto)return {sa:null,monto:0};
  if(tipo==="abono"){const s0=await saldoHistorial(tid,A);if(monto>s0)monto=s0;if(!monto)return {sa:s0,monto:0,total:(await saldosTienda(tid)).total};}
  const{error}=await db.from("creditos_mov").insert({tienda_id:tid,tipo,monto,detalle:limpia(detalle,160),por,acreedor:A});
  if(error)throw new Error("No se pudo registrar el "+tipo+" en el historial: "+error.message);
  const st=await saldosTienda(tid);
  await db.from("tiendas").update({sa:st.por.dueno||0}).eq("id",tid);
  return {sa:st.por[A]||0,monto,total:st.total};
}
/* 182 · cobros por PEPS: cada pago cancela primero la deuda más antigua de ESE acreedor.
   Deja, por cada deuda: quién fió, cuándo, cuánto ya se pagó, quién lo cobró y cuánto falta. */
async function deudasDetalle(tid){
  const{data}=await db.from("creditos_mov").select("*").eq("tienda_id",tid);
  const movs=(data||[]).slice().sort((a,b)=>(new Date(a.creado)-new Date(b.creado))||(a.id-b.id));
  const cuentas={};
  movs.forEach(m=>{
    const a=acreedorDe(m),c=cuentas[a]||(cuentas[a]={acreedor:a,cargos:[],saldo:0,a_favor:0});
    const monto=Number(m.monto||0);
    if(m.tipo==="cargo"){c.cargos.push({id:m.id,fecha:m.creado,por:m.por,detalle:m.detalle,monto,pagado:0,pendiente:monto,cobros:[]});return;}
    let resto=monto;
    for(const g of c.cargos){if(resto<=0)break;if(g.pendiente<=0)continue;
      const x=Math.min(resto,g.pendiente);g.pagado=Math.round((g.pagado+x)*100)/100;g.pendiente=Math.round((g.pendiente-x)*100)/100;
      g.cobros.push({por:m.por,fecha:m.creado,monto:Math.round(x*100)/100});resto-=x;}
    if(resto>0.004)c.a_favor=Math.round((c.a_favor+resto)*100)/100;
  });
  Object.values(cuentas).forEach(c=>{
    c.saldo=Math.round(c.cargos.reduce((s,g)=>s+g.pendiente,0)*100)/100;
    c.cargos.forEach(g=>{g.estado=g.pendiente<=0.004?"pagado":(g.pagado>0?"parcial":"pendiente");});
  });
  return Object.values(cuentas);
}
async function nombresAcreedores(){
  const[{data:cs},P]=await Promise.all([db.from("conductores").select("usuario,nombre"),getParams()]);
  const m={dueno:((P.negocio&&P.negocio.nombre)?(P.negocio.nombre+" (dueño)"):"el dueño")};
  (cs||[]).forEach(c=>{m[c.usuario]=c.nombre||c.usuario;});
  return m;
}
async function evento(tipo,titulo,desc,ref){await db.from("eventos").insert({tipo,titulo,descripcion:desc,ref:String(ref||""),visto:false});}
async function avisoA(para,txt){await db.from("avisos").insert({para,txt,hora:horaPE()});}
async function tiendaPorNombre(n){
  if(!n)return null;
  const{data}=await db.from("tiendas").select("*").ilike("nombre",String(n).trim()).maybeSingle();
  if(data)return data;
  const{data:ap}=await db.from("tiendas").select("*").ilike("nombre","%"+String(n).trim().slice(0,20)+"%").limit(2);
  return (ap&&ap.length===1)?ap[0]:null;   // solo si es inequívoca
}
async function getParams(){const{data}=await db.from("params").select("*").eq("id",1).maybeSingle();return (data&&data.kv)||{};}


// ════════ RITMO DE REPOSICIÓN DE CADA TIENDA ════════
// La escala de 8 niveles nunca fue una escala de días: es una escala de CICLOS.
// Si divides cada corte de la escala vieja entre 3, salen los mismos números
// (el nivel 3 cae exactamente en 1,00 ciclo). Ese 3 estaba escrito a mano en
// cada corte. Ahora vive en el ritmo de cada tienda, así que el mismo código
// sirve para una tienda activa (ciclo 3), una semanal (ciclo 7) y cualquier
// ritmo que se añada después desde Configuración, sin tocar la base.
const RITMOS_BASE=[
  {id:"activa", nombre:"Activa",  emoji:"\u{1F3EA}", ciclo_dias:3, umbral_repo:40, resta_parcial:2,
   dias_perdido:30, pesos:[5,12,22,45,65,80],
   desc:"Vende su mercader\u00eda en unos 3 d\u00edas. Alto movimiento, punto estrat\u00e9gico."},
  {id:"semanal",nombre:"Semanal", emoji:"\u{1F4C5}", ciclo_dias:7, umbral_repo:90, resta_parcial:5,
   dias_perdido:45, pesos:[3,8,25,42,58,72],
   desc:"Tarda una semana en vender su mercader\u00eda. Movimiento m\u00e1s lento."}
];
function ritmosDe(params){
  const l=(params&&Array.isArray(params.ritmos)&&params.ritmos.length)?params.ritmos:RITMOS_BASE;
  return l.map(r=>{
    const base=RITMOS_BASE.find(x=>x.id===r.id)||RITMOS_BASE[0];
    const pe=Array.isArray(r.pesos)&&r.pesos.length===6?r.pesos.map(x=>num(x,0,999)||0):base.pesos;
    return {id:limpia(r.id,20)||"activa", nombre:String(r.nombre||r.id||"").slice(0,30)||base.nombre,
      emoji:String(r.emoji||base.emoji).slice(0,4),
      ciclo_dias:num(r.ciclo_dias,1,120)||base.ciclo_dias,
      umbral_repo:num(r.umbral_repo,1,100000)||base.umbral_repo,
      resta_parcial:num(r.resta_parcial,0,60)||base.resta_parcial,
      dias_perdido:num(r.dias_perdido,7,365)||base.dias_perdido,
      pesos:pe, desc:String(r.desc||base.desc||"").slice(0,160)};
  });
}
function ritmoDe(params,id){
  const l=ritmosDe(params);
  return l.find(r=>r.id===String(id||"activa"))||l[0];
}
// Cortes en ciclos, no en días. Los niveles 1 a 6 son proporcionales al ciclo;
// el 7 y el 8 son de calendario (dias_perdido), porque perder un cliente es un
// hecho de tiempo real, no de ciclos: nadie espera 10 ciclos de una semanal.
const CORTES_CICLO=[0.35,0.75,1.0,1.45,1.9,3.4];
function nivelDe(d,ritmo){
  const c=Number(ritmo&&ritmo.ciclo_dias)||3, dd=Math.max(0,Number(d)||0), r=dd/c;
  for(let i=0;i<CORTES_CICLO.length;i++) if(r<=CORTES_CICLO[i]+1e-9) return i+1;
  return (dd < (Number(ritmo&&ritmo.dias_perdido)||30)) ? 7 : 8;
}
const NIVEL_TXT=["","Reci\u00e9n surtida","Con mercader\u00eda","Por terminar","Reponer imprescindible",
  "Posible desabastecimiento","Visitar necesariamente","Posible cliente perdido","Cliente perdido"];
function puntajeDe(d,ritmo,vip,pedidoHoy,dias,pesoCerrada){
  const n=nivelDe(d,ritmo);
  if(n>=7)return {sc:0,nivel:n,abre:true,why:NIVEL_TXT[n]+" \u2014 alerta admin, no entra a ruta"};
  let b=(ritmo&&ritmo.pesos&&ritmo.pesos[n-1])!=null?Number(ritmo.pesos[n-1]):0;
  const w=[NIVEL_TXT[n]+" ("+d+"d)"];
  if(vip&&n>=4){b=Math.round(b*1.5);w.push("\u2605 VIP potencia (desde nivel 4)");}
  else if(vip){w.push("VIP sin efecto (nivel <4)");}
  /* Hoy cerrada: no se excluye, baja de prioridad y se marca. Si el dato de
     días estuviera mal cargado, la tienda sigue visible al final de la lista
     en vez de desaparecer sin que nadie se entere. */
  const abre=(dias==null)?true:abreHoy(dias);
  if(!abre){
    const f=Math.max(0,Math.min(1,pesoCerrada==null?0.15:Number(pesoCerrada)));
    b=Math.round(b*f);
    w.push("\u{1F6AB} hoy no atiende");
  }
  /* Un pedido de hoy se suma DESPUÉS del castigo por cierre: si la tienda
     pidió mercadería hoy es que hoy está, y ese hecho real pesa más que un
     dato de días que puede estar viejo. Además se marca la contradicción. */
  if(pedidoHoy){
    b+=100;
    w.push(abre?"\u{1F4E9} Pedido de hoy \u2014 garantizado"
               :"\u{1F4E9} Pedido de hoy \u2014 garantizado (pidi\u00f3 en un d\u00eda marcado como cerrado: revisa sus d\u00edas)");
  }
  return {sc:b,nivel:n,abre,why:w.join(" \u00b7 ")};
}
// Días desde la última compra buena, con el descuento por compras chicas.
// Una sola definición: la usan igual la app del conductor y el panel.
function diasRepo(ventasDeLaTienda,ritmo,drAjuste,drBase,dias){
  const UMB=Number(ritmo&&ritmo.umbral_repo)||40, RESTA=Number(ritmo&&ritmo.resta_parcial)||2;
  const CIC=Number(ritmo&&ritmo.ciclo_dias)||3;
  const vs=ventasDeLaTienda||[];
  const iBig=vs.findIndex(v=>Number(v.total||0)>=UMB);
  const baseV=iBig>=0?vs[iBig]:(vs.length?vs[vs.length-1]:null);
  const nBajas=iBig>=0?iBig:vs.length;
  let diasBase;
  if(baseV){
    const t0=new Date(baseV.creado).getTime();
    const cal=Math.round((Date.now()-t0)/86400000);
    diasBase=diasAbiertosTras(t0,cal,dias);   // solo los días que atiende
  }else diasBase=(drBase==null?3:drBase);
  /* El crédito por compras chicas no puede pasar de UN ciclo entero.
     Sin este tope, una tienda con muchas compras chicas y ninguna buena
     restaba tantos días que salía "Recién surtida" llevando semanas sin
     comprar de verdad: 13 compras chicas × 2 días = 26 días de descuento.
     Todas las compras chicas juntas valen, como mucho, una reposición. */
  const credito=Math.min(RESTA*nBajas,CIC);
  return Math.max(0,diasBase-credito-(Number(drAjuste)||0));
}


// ════════ DÍAS EN QUE LA TIENDA ATIENDE ════════
// Siete caracteres, lunes a domingo. '1' atiende, '0' no atiende.
// ('2' queda reservado para "día fuerte / de feria" sin migrar nada.)
// Antes esto era un texto libre (dias_no) que se comparaba buscando la
// palabra del día dentro de la cadena: "domingos" funcionaba, "dom" no,
// y nadie se enteraba del fallo.
const DIA_NOM=["lunes","martes","miércoles","jueves","viernes","sábado","domingo"];
const DIA_COR=["L","M","M","J","V","S","D"];
// Perú no tiene horario de verano: siempre UTC-5.
function diaIdx(ms){const d=new Date((ms==null?Date.now():ms)-5*3600000);return (d.getUTCDay()+6)%7;}
function diasNorm(v){
  let t=String(v==null?"":v).replace(/[^012]/g,"");
  if(t.length!==7)t="1111111";
  if(t.indexOf("1")<0&&t.indexOf("2")<0)t="1111111"; // nunca cerrada los 7 días
  return t;
}
function abreEl(dias,idx){return diasNorm(dias).charAt(idx)!=="0";}
function abreHoy(dias){return abreEl(dias,diaIdx());}
function diasAbiertosSemana(dias){const t=diasNorm(dias);let n=0;for(let i=0;i<7;i++)if(t.charAt(i)!=="0")n++;return n;}
// Texto legible, y compatibilidad con el campo viejo dias_no
function diasNoTexto(dias){
  const t=diasNorm(dias),f=[];
  for(let i=0;i<7;i++)if(t.charAt(i)==="0")f.push(DIA_NOM[i]);
  if(!f.length)return "";
  if(f.length===1)return f[0];
  return f.slice(0,-1).join(", ")+" y "+f[f.length-1];
}
function diasTexto(dias){
  const t=diasNorm(dias);
  if(diasAbiertosSemana(t)===7)return "todos los días";
  return DIA_COR.map((d,i)=>t.charAt(i)==="0"?"·":d).join(" ");
}
// Cuántos DÍAS DE ATENCIÓN hay en los N días de calendario posteriores a `desde`.
// Una tienda que cierra dos días por semana no vacía su mercadería en 3 días
// de calendario sino en 5: está cerrada, no está vendiendo. Contar solo los
// días que atiende es lo que hace que el ciclo signifique lo mismo para todas.
function diasAbiertosTras(desdeMs,nCal,dias){
  const t=diasNorm(dias), porSem=diasAbiertosSemana(t);
  if(porSem===7)return nCal;                 // caso normal: nada cambia
  const n=Math.max(0,Math.floor(nCal));
  const semanas=Math.floor(n/7), resto=n%7;
  let c=semanas*porSem;
  const ini=diaIdx(desdeMs);
  for(let k=1;k<=resto;k++)if(t.charAt((ini+k)%7)!=="0")c++;
  return c;
}

function pipSrv(lat,lon,poly){let d=false;for(let i=0,j=poly.length-1;i<poly.length;j=i++){const yi=poly[i][0],xi=poly[i][1],yj=poly[j][0],xj=poly[j][1];if(((yi>lat)!==(yj>lat))&&(lon<(xj-xi)*(lat-yi)/(yj-yi)+xi))d=!d;}return d;}
let ZONAS_CACHE={t:0,z:[]};
async function zonasVivas(){if(Date.now()-ZONAS_CACHE.t<60000)return ZONAS_CACHE.z;const p=await getParams();ZONAS_CACHE={t:Date.now(),z:(p.zonas||[]).filter(z=>Array.isArray(z.poligono)&&z.poligono.filter(q=>q&&q[0]&&q[1]).length>=3)};return ZONAS_CACHE.z;}
function zonaDeCond(lat,lon,u){if(lat==null||lon==null)return undefined;for(const z of (ZONAS_CACHE.z||[]))if(z.poligono&&pipSrv(lat,lon,z.poligono))return z.conductor?(z.conductor===u?"mia":"otra"):undefined;return undefined;}

// ── auth middlewares ──
function authC(req,res,next){try{req.cond=jwt.verify(req.headers["x-token"]||"",SECRET);if(req.cond.a||!USR_RE.test(req.cond.u||""))throw 0;next();}catch(e){res.status(401).json({ok:false,error:"Sesión inválida"});}}
function authA(req,res,next){
  try{
    const t=jwt.verify(req.headers["x-admin"]||"",SECRET);
    if(!t.a)throw 0;
    req.ro=!!t.ro;
    if(req.ro&&req.method!=="GET")return res.status(403).json({ok:false,error:"Modo solo lectura: no puedes hacer cambios"});
    next();
  }catch(e){res.status(401).json({ok:false,error:"Admin no autenticado"});}
}

// ════════ SALUD ════════
const fs=require("fs");
const path=require("path");
/* ═══ 181 · LUGARES: distritos oficiales del Perú (distritos-peru.json, INEI 2026) ═══
   · Cada tienda toma su distrito por GPS (columna ubigeo, 6 dígitos INEI). El dueño
     puede corregirlo a mano (lug_manual) para tiendas pegadas a un límite.
   · Cada conductor tiene lugares habilitados: prefijos de departamento (2 dígitos),
     provincia (4) o distrito (6), con excepciones. Manda el prefijo más específico.
     Sin lugares: el empleado ve todas las tiendas; el independiente, ninguna.
   · Zona protegida (hoy el distrito Espinar, 080801): el independiente solo ve ahí las
     tiendas que el dueño le habilite una por una, más las que él mismo registre. */
let GEO=null;
function geo(){
  if(GEO)return GEO;
  try{GEO=JSON.parse(fs.readFileSync(path.join(__dirname,"distritos-peru.json"),"utf8"));}
  catch(e){console.log("Lugares: falta distritos-peru.json en el repositorio →",e.message);GEO={dist:[],dep:{},prov:{},escala:1e4,falta:true};}
  GEO.idx={};(GEO.dist||[]).forEach(d=>{GEO.idx[d[0]]=d;});
  return GEO;
}
function enAnillo(x,y,r){let d=false;for(let i=0,j=r.length-2;i<r.length;j=i,i+=2){const xi=r[i],yi=r[i+1],xj=r[j],yj=r[j+1];if(((yi>y)!==(yj>y))&&(x<(xj-xi)*(y-yi)/(yj-yi)+xi))d=!d;}return d;}
function ubicarGPS(lat,lon){
  lat=Number(lat);lon=Number(lon);if(!isFinite(lat)||!isFinite(lon)||(!lat&&!lon))return null;
  const G=geo(),E=G.escala||1e4,x=Math.round(lon*E),y=Math.round(lat*E);
  for(const d of G.dist){const b=d[2];if(x<b[0]||x>b[2]||y<b[1]||y>b[3])continue;
    for(const pol of d[3])if(enAnillo(x,y,pol[0])&&!pol.slice(1).some(h=>enAnillo(x,y,h)))return d[0];}
  return null;
}
const PREF_RE=/^\d{2}(\d{2}(\d{2})?)?$/;
function lugarValido(p){p=String(p||"");if(!PREF_RE.test(p))return false;const G=geo();
  return p.length===2?!!G.dep[p]:(p.length===4?!!G.prov[p]:!!G.idx[p]);}
function nombreLugar(p){
  p=String(p||"");if(!p)return "";const G=geo(),partes=[];
  if(p.length>=6&&G.idx[p.slice(0,6)])partes.push(G.idx[p.slice(0,6)][1]);
  if(p.length>=4&&G.prov[p.slice(0,4)])partes.push(G.prov[p.slice(0,4)]);
  if(G.dep[p.slice(0,2)])partes.push(G.dep[p.slice(0,2)]);
  return partes.join(", ");
}
/* «fijo» y «paso» son los nombres viejos: se leen como empleado e independiente */
const tipoNorm=v=>{v=String(v||"").toLowerCase();return (v==="paso"||v==="independiente")?"independiente":"empleado";};
const tipoDe=c=>tipoNorm(c&&c.tipo);
function lugaresDe(c){
  const L=(c&&c.lugares&&typeof c.lugares==="object")?c.lugares:{};
  return {inc:(Array.isArray(L.inc)?L.inc:[]).filter(p=>PREF_RE.test(p)),exc:(Array.isArray(L.exc)?L.exc:[]).filter(p=>PREF_RE.test(p))};
}
function habilitadoEn(c,ub){
  const L=lugaresDe(c);
  if(!L.inc.length)return tipoDe(c)==="empleado";
  if(!ub)return tipoDe(c)==="empleado";
  let mejor=null;
  L.inc.forEach(p=>{if(ub.startsWith(p)&&(!mejor||p.length>mejor.p.length))mejor={p,s:true};});
  L.exc.forEach(p=>{if(ub.startsWith(p)&&(!mejor||p.length>=mejor.p.length))mejor={p,s:false};});
  return !!(mejor&&mejor.s);
}
const protegidas=P=>Array.isArray(P&&P.protegidas)?P.protegidas.filter(p=>PREF_RE.test(p)):["080801"];
const esProtegida=(P,ub)=>!!ub&&protegidas(P).some(p=>ub.startsWith(p));
function puedeVer(c,t,P){
  if(!c||!t||t.act===false)return false;
  const u=c.usuario,est=t.estado_reg||"ok";
  if(est==="rechazada"||est==="fusionada")return false;
  if(t.conductor_reg===u)return true;                        // las que él registró (también pendientes)
  if(est==="pendiente")return false;                          // pendiente de otro: no la ve nadie más
  if((Array.isArray(t.habilitados)?t.habilitados:[]).includes(u))return true;   // habilitada a mano
  if(!habilitadoEn(c,t.ubigeo))return false;
  if(tipoDe(c)==="independiente"&&esProtegida(P,t.ubigeo))return false;
  return true;
}
function limiteLugar(P,ub){
  const m=(P&&P.limite_lugar&&typeof P.limite_lugar==="object")?P.limite_lugar:{};
  let mejor=null;Object.keys(m).forEach(p=>{if(ub&&String(ub).startsWith(p)&&(!mejor||p.length>mejor.length))mejor=p;});
  return mejor?num(m[mejor],0,100000,0):(num(P&&P.limite_credito,0,100000,230)||230);
}
function resumenLugares(c){
  const L=lugaresDe(c);
  if(!L.inc.length)return tipoDe(c)==="empleado"?"Sin lugares: ve todas las tiendas":"Sin lugares: no ve ninguna tienda";
  return L.inc.map(nombreLugar).join(" · ")+(L.exc.length?(" (menos "+L.exc.map(nombreLugar).join(", ")+")"):"");
}
/* repetidas: se compara con TODAS las tiendas, también las que el conductor no ve */
const normN=x=>String(x||"").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g,"")
  .replace(/\b(tienda|bodega|minimarket|market|la|el|de|del|los|las|don|dona|sra|sr)\b/g," ").replace(/[^a-z0-9]/g,"");
function metrosEntre(a,b,c,d){const R=6371000,k=Math.PI/180,x=Math.sin((c-a)*k/2)**2+Math.cos(a*k)*Math.cos(c*k)*Math.sin((d-b)*k/2)**2;return Math.round(2*R*Math.asin(Math.sqrt(x)));}
async function buscarRepetida(nombre,lat,lon,P){
  const radio=num((P&&P.operacion&&P.operacion.radio_dup_m)||(P&&P.dup_radio_m),1,500,15),nn=normN(nombre);
  const{data:ts}=await db.from("tiendas").select("id,nombre,lat,lon,act,estado_reg").eq("act",true);
  let mejor=null;
  (ts||[]).forEach(t=>{
    if(t.estado_reg==="rechazada"||t.estado_reg==="fusionada")return;
    const m=(lat!=null&&lon!=null&&t.lat!=null&&t.lon!=null)?metrosEntre(lat,lon,Number(t.lat),Number(t.lon)):null;
    const nt=normN(t.nombre),mismo=nn.length>=3&&nt===nn, cerca=(m!=null&&m<=radio);
    /* 182 · nombre parecido (uno contiene al otro, 4+ letras) a menos de 50 m */
    const parecido=!mismo&&nn.length>=4&&nt.length>=4&&(nt.indexOf(nn)>=0||nn.indexOf(nt)>=0)&&m!=null&&m<=50;
    if(cerca||parecido||(mismo&&(m==null||m<=300))){const pt=(cerca?1000-m:0)+(mismo?500:0)+(parecido?200:0);if(!mejor||pt>mejor.pt)mejor={t,m,pt};}
  });
  return mejor;
}
async function recalcularLugares(todas){
  const{data:ts}=await db.from("tiendas").select("id,nombre,lat,lon,ubigeo,lug_manual");
  let n=0;
  for(const t of (ts||[])){
    if(t.lug_manual||t.lat==null||t.lon==null)continue;
    if(!todas&&t.ubigeo)continue;
    const ub=ubicarGPS(t.lat,t.lon);
    if(ub&&ub!==t.ubigeo){await db.from("tiendas").update({ubigeo:ub}).eq("id",t.id);n++;}
  }
  return n;
}
setTimeout(async()=>{try{geo();const n=await recalcularLugares(false);if(n)console.log("Lugares: "+n+" tiendas ubicadas en su distrito");}catch(e){console.log("Lugares:",e.message);}},8000);
/* ═══ 184 · FASE 2: PEDIDOS Y PRECIOS ACORDADOS ═══
   · Código de tienda DEP-PRO-NNNN (ej. CUS-ESP-0045): departamento y provincia con
     abreviaturas FIJAS (ISO para los departamentos; las provincias, tabla congelada aquí)
     y el número de la tienda dentro de su provincia. Se asigna una vez y no cambia nunca,
     aunque después se corrija su distrito.
   · Un pedido pasa por «Por confirmar» (link, mensaje pegado, foto) o nace confirmado (lo
     registra el dueño). Confirmado = vigente hasta que alguien lo entregue: lo atiende la
     venta a esa tienda. «No pude» lo devuelve al dueño. Pasado su día, queda atrasado.
   · Precio acordado: el que un conductor cambió al vender queda para esa tienda. */
const ABREV_DEP={"10":"HUC","11":"ICA","12":"JUN","13":"LAL","14":"LAM","15":"LIM","16":"LOR","17":"MDD","18":"MOQ","19":"PAS","20":"PIU","21":"PUN","22":"SAM","23":"TAC","24":"TUM","25":"UCA","01":"AMA","02":"ANC","03":"APU","04":"ARE","05":"AYA","06":"CAJ","07":"CAL","08":"CUS","09":"HUV"};
const ABREV_PRO=Object.fromEntries("0101:CHA,0102:BAG,0103:BON,0104:CON,0105:LUY,0106:RME,0107:UTC,0201:HUA,0202:AIJ,0203:ARA,0204:ASU,0205:BOL,0206:CAR,0207:CFF,0208:CAS,0209:COR,0210:HRI,0211:HRM,0212:HYL,0213:MLU,0214:OCR,0215:PAL,0216:POM,0217:REC,0218:SAN,0219:SIH,0220:YUN,0301:ABA,0302:AND,0303:ANT,0304:AYM,0305:COT,0306:CHI,0307:GRA,0401:ARE,0402:CAM,0403:CAR,0404:CAS,0405:CAY,0406:CON,0407:ISL,0408:UNI,0501:HUA,0502:CAN,0503:HSA,0504:HNT,0505:MAR,0506:LUC,0507:PAR,0508:PSS,0509:SUC,0510:VFA,0511:VHU,0601:CAJ,0602:CJB,0603:CEL,0604:CHO,0605:CON,0606:CUT,0607:HUA,0608:JAE,0609:SIG,0610:SMA,0611:SMI,0612:SPA,0613:SCR,0701:PCC,0801:CUS,0802:ACO,0803:ANT,0804:CAL,0805:CAN,0806:CNC,0807:CHU,0808:ESP,0809:CON,0810:PAR,0811:PAU,0812:QUI,0813:URU,0901:HUA,0902:ACO,0903:ANG,0904:CAS,0905:CHU,0906:HYT,0907:TAY,1001:HUA,1002:AMB,1003:DMA,1004:HCY,1005:HML,1006:LPR,1007:MAR,1008:PAC,1009:PIN,1010:LAU,1011:YAR,1101:ICA,1102:CHI,1103:NAS,1104:PAL,1105:PIS,1201:HUA,1202:CON,1203:CHA,1204:JAU,1205:JUN,1206:SAT,1207:TAR,1208:YAU,1209:CHU,1301:TRU,1302:ASC,1303:BOL,1304:CHE,1305:JUL,1306:OTU,1307:PAC,1308:PAT,1309:SCA,1310:SCH,1311:GCH,1312:VIR,1401:CHI,1402:FER,1403:LAM,1501:LIM,1502:BAR,1503:CAJ,1504:CAN,1505:CNT,1506:HUA,1507:HRC,1508:HRA,1509:OYO,1510:YAU,1601:MAY,1602:AAM,1603:LOR,1604:MRC,1605:REQ,1606:UCA,1607:DMA,1608:PUT,1701:TAM,1702:MAN,1703:TAH,1801:MNI,1802:GSC,1803:ILO,1901:PAS,1902:DAC,1903:OXA,2001:PIU,2002:AYA,2003:HUA,2004:MOR,2005:PAI,2006:SUL,2007:TAL,2008:SEC,2101:PUN,2102:AZA,2103:CAR,2104:CHU,2105:COL,2106:HUA,2107:LAM,2108:MEL,2109:MOH,2110:SAP,2111:SRO,2112:SAN,2113:YUN,2201:MOY,2202:BEL,2203:DOR,2204:HUA,2205:LAM,2206:MCA,2207:PIC,2208:RIO,2209:SMA,2210:TOC,2301:TAC,2302:CAN,2303:JBA,2304:TAR,2401:TUM,2402:CVI,2403:ZAR,2501:CPO,2502:ATA,2503:PAB,2504:PUR".split(",").map(x=>x.split(":")));
function prefijoCodigo(ub){ub=String(ub||"");const d=ABREV_DEP[ub.slice(0,2)],p=ABREV_PRO[ub.slice(0,4)];return (d&&p)?(d+"-"+p):null;}
let _codCorre=false;
async function asegurarCodigos(){
  if(_codCorre)return 0;_codCorre=true;
  try{
    const{data:ts}=await db.from("tiendas").select("id,ubigeo,codigo,estado_reg").order("id",{ascending:true});
    const max={};
    (ts||[]).forEach(t=>{const m=String(t.codigo||"").match(/^([A-Z]{3}-[A-Z]{3})-(\d+)$/);if(m)max[m[1]]=Math.max(max[m[1]]||0,parseInt(m[2],10));});
    let n=0;
    for(const t of (ts||[])){
      if(t.codigo||!t.ubigeo||(t.estado_reg&&t.estado_reg!=="ok"))continue;
      const pre=prefijoCodigo(t.ubigeo);if(!pre)continue;
      const k=(max[pre]||0)+1;max[pre]=k;
      const{error}=await db.from("tiendas").update({codigo:pre+"-"+String(k).padStart(4,"0")}).eq("id",t.id).is("codigo",null);
      if(!error)n++;
    }
    return n;
  }catch(e){console.log("códigos:",e.message);return 0;}
  finally{_codCorre=false;}
}
const cryptoR=require("crypto");
const PED_VIG=["pendiente","devuelto"];
const normTxt=s=>String(s||"").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g,"").replace(/[^a-z0-9 ]/g," ").replace(/\s+/g," ").trim();
const fechaOK=f=>/^\d{4}-\d{2}-\d{2}$/.test(String(f||""))&&!isNaN(new Date(String(f)+"T12:00:00Z").getTime());
const sumarDias=(f,n)=>new Date(new Date(f+"T12:00:00Z").getTime()+n*86400000).toISOString().slice(0,10);
const diaDe=f=>diaIdx(new Date(String(f).slice(0,10)+"T12:00:00-05:00").getTime());
function fechaTxt(f){
  f=String(f||"").slice(0,10);if(!fechaOK(f))return "";
  const h=hoy();if(f===h)return "hoy";if(f===sumarDias(h,1))return "mañana";if(f===sumarDias(h,-1))return "ayer";
  return DIA_NOM[diaDe(f)]+" "+Number(f.slice(8,10))+"/"+Number(f.slice(5,7));
}
const txtItems=(its,visita)=>visita?"🚚 que pase el camión (elige al verlo)":((Array.isArray(its)?its:[]).map(x=>x.c+" "+(x.n||x.p||"")).join(", ")||"—");
/* productos activos (de categorías activas), para validar y para el link */
async function catalogoPed(){
  const[{data:cat},{data:cats}]=await Promise.all([
    db.from("catalogo").select("id,cat,nombre,activo,no_tipos,orden").or("activo.is.null,activo.eq.true"),
    db.from("categorias").select("id,nom,emoji,orden,activa").eq("activa",true).order("orden")]);
  const cv=new Set((cats||[]).map(c=>c.id));
  const prods=(cat||[]).filter(p=>cv.has(p.cat)).sort((a,b)=>(Number(a.orden||0)-Number(b.orden||0))||String(a.nombre).localeCompare(String(b.nombre)));
  return {prods,cats:cats||[],por:Object.fromEntries(prods.map(p=>[p.id,p]))};
}
/* [{id,n,c}] solo con productos que existen; admite el formato viejo {p,c} (sin id) */
function itemsPed(items,C){
  const out=[],vistos={};
  (Array.isArray(items)?items:[]).slice(0,80).forEach(x=>{
    if(!x||typeof x!=="object")return;
    const c=Math.round(num(x.c,0,999,0));if(!c)return;
    const id=limpia(x.id,40);
    if(id){if(!C.por[id])return;if(vistos[id]){vistos[id].c=Math.min(999,vistos[id].c+c);return;}
      const it={id,n:C.por[id].nombre,c};vistos[id]=it;out.push(it);return;}
    const n=limpia(x.p||x.n,60);if(n)out.push({n,c});
  });
  return out;
}
const telPE=v=>{const d=String(v||"").replace(/\D/g,"");if(/^9\d{8}$/.test(d))return "51"+d;if(/^519\d{8}$/.test(d))return d;return null;};
function sugeridosDe(t,conds,P){
  const act=(conds||[]).filter(c=>c.activo!==false);
  const si=t?act.filter(c=>puedeVer(c,t,P)):[];
  return si.map(c=>({u:c.usuario,n:c.nombre||c.usuario,tipo:tipoDe(c)}))
    .concat(act.filter(c=>!si.includes(c)).map(c=>({u:c.usuario,n:c.nombre||c.usuario,tipo:tipoDe(c),fuera:true})));
}
/* deja vigente un pedido (confirmado, con conductor) y reemplaza al anterior sin entregar de esa tienda */
async function activarPedido(p,conductor){
  const upd={estado:"pendiente",conductor,confirmado_en:new Date().toISOString()};
  let f=fechaOK(p.fecha&&String(p.fecha).slice(0,10))?String(p.fecha).slice(0,10):hoy();
  if(p.lo_antes||f<hoy())f=hoy();
  upd.fecha=f;
  await db.from("pedidos").update(upd).eq("id",p.id);
  Object.assign(p,upd);
  let reemp=[];
  if(p.tienda_id){
    const{data:otros}=await db.from("pedidos").select("id,estado,creado,conductor").eq("tienda_id",p.tienda_id).in("estado",["pendiente","devuelto","por_confirmar"]);
    reemp=(otros||[]).filter(o=>o.id!==p.id&&(o.estado!=="por_confirmar"||new Date(o.creado)<=new Date(p.creado||Date.now())));
    for(const o of reemp){
      await db.from("pedidos").update({estado:"reemplazado",reemplazado_por:p.id}).eq("id",o.id);
      if(o.estado==="pendiente"&&o.conductor&&o.conductor!==conductor)await avisoA(o.conductor,"↩️ El pedido de «"+(p.tienda||"una tienda")+"» cambió y ya no te toca a ti.");
    }
  }
  await avisoA(conductor,"📩 Pedido para "+fechaTxt(f)+" — «"+(p.tienda||"")+"»: "+txtItems(p.items,p.visita)+(p.nota?(" · "+p.nota):""));
  let aviso=null;
  if(p.tienda_id){
    const{data:t}=await db.from("tiendas").select("nombre,dias_atiende").eq("id",p.tienda_id).maybeSingle();
    if(t&&!abreEl(t.dias_atiende,diaDe(f))){
      aviso="⚠️ "+t.nombre+" no atiende los "+DIA_NOM[diaDe(f)]+" según sus días cargados. El pedido queda registrado igual.";
      const P=await getParams();
      if(((P.dias_cfg||{}).avisar_pedido)!==false)
        await evento("pedido_dia","📅 Pedido para un día que no atiende — "+t.nombre,"El pedido es para el "+DIA_NOM[diaDe(f)]+" "+f+", pero esa tienda tiene marcado que no atiende ese día ("+diasTexto(t.dias_atiende)+"). Revisa si los días están bien cargados.",String(p.tienda_id));
    }
  }
  return {reemplazados:reemp.map(o=>o.id),aviso};
}
/* la venta (o la visita, si pidió que pase el camión) atiende el pedido vigente de esa tienda */
async function atenderPedido(t,u,v,items,esVisita){
  const{data:ps}=await db.from("pedidos").select("*").in("estado",PED_VIG);
  const nt=String(t.nombre||"").toLowerCase().trim();
  const suyos=(ps||[]).filter(p=>(p.tienda_id&&p.tienda_id===t.id)||(!p.tienda_id&&String(p.tienda||"").toLowerCase().trim()===nt));
  if(!suyos.length)return [];
  const vend=(Array.isArray(items)?items:[]).filter(x=>x&&x.id).map(x=>({id:x.id,n:x.n,c:num(x.c,0,9999)}));
  const{data:yo}=await db.from("conductores").select("nombre").eq("usuario",u).maybeSingle();
  const quien=(yo&&yo.nombre)||u,hechos=[];
  for(const p of suyos){
    if(esVisita&&!p.visita)continue;
    const f=String(p.fecha||hoy()).slice(0,10);
    /* desde el día del pedido lo atiende cualquiera; antes, solo el asignado si lleva algo del pedido */
    const toca=f<=hoy()||(p.conductor===u&&(p.visita||(p.items||[]).some(x=>x&&x.id&&vend.some(y=>y.id===x.id))));
    if(!toca)continue;
    await db.from("pedidos").update({estado:"atendido",atendido_por:u,atendido_en:new Date().toISOString(),venta_id:v?v.id:null,vendido:esVisita?[]:vend}).eq("id",p.id);
    if(p.conductor&&p.conductor!==u)await avisoA(p.conductor,"✅ El pedido de «"+t.nombre+"» ya lo atendió "+quien+". Ya no hace falta que lo lleves.");
    await evento("pedido_atendido","✅ Pedidos atendidos",t.nombre+(t.codigo?(" ("+t.codigo+")"):"")+" · lo atendió "+quien
      +((p.conductor&&p.conductor!==u)?(" (estaba asignado a "+p.conductor+")"):"")+" · pidió: "+txtItems(p.items,p.visita)
      +(esVisita?" · la visitó y no compró":(" · vendió: "+(vend.map(x=>x.c+" "+x.n).join(", ")||"—"))),String(p.id));
    hechos.push(p.id);
  }
  return hechos;
}
/* precio acordado: lo que el conductor cambió al vender queda como precio de esa tienda */
async function guardarAcordados(t,u,pa,P){
  if(!pa||typeof pa!=="object"||Array.isArray(pa)||!Object.keys(pa).length)return 0;
  const{data:yo}=await db.from("conductores").select("usuario,nombre,tipo").eq("usuario",u).maybeSingle();
  const ind=tipoDe(yo)==="independiente";
  if(!ind&&P&&P.catalogo_cfg&&P.catalogo_cfg.conductor_cambia_precio===false)return 0;
  const ids=Object.keys(pa).slice(0,200).map(k=>limpia(k,40)).filter(Boolean);
  if(!ids.length)return 0;
  const{data:cat}=await db.from("catalogo").select("id,nombre").in("id",ids);
  const nom={};(cat||[]).forEach(p=>{nom[p.id]=p.nombre;});
  const{data:tt}=await db.from("tiendas").select("precios").eq("id",t.id).maybeSingle();
  const pr=Object.assign({},(tt&&tt.precios&&typeof tt.precios==="object"&&!Array.isArray(tt.precios))?tt.precios:{});
  const cambios=[];
  ids.forEach(id=>{
    if(!nom[id])return;const x=(pa[id]&&typeof pa[id]==="object")?pa[id]:{};
    const r2=v=>Math.round(num(v,0,100000,0)*100)/100;
    const ahora=r2(x.ahora),antes=r2(x.antes),base=r2(x.cat);
    if(!(ahora>0)||Math.abs(ahora-antes)<0.005)return;
    if(base>0&&Math.abs(ahora-base)<0.005)delete pr[id];else pr[id]=ahora;
    cambios.push(nom[id]+" de S/"+antes.toFixed(2)+" a S/"+ahora.toFixed(2));
  });
  if(!cambios.length)return 0;
  await db.from("tiendas").update({precios:pr}).eq("id",t.id);
  await evento("precio_acordado","💲 Precios acordados",t.nombre+": "+cambios.slice(0,8).join(", ")+(cambios.length>8?(" y "+(cambios.length-8)+" más"):"")
    +" — acordado por "+((yo&&yo.nombre)||u)+(ind?" (independiente)":"")+". Desde ahora es su precio.",String(t.id));
  return cambios.length;
}
/* ── camino 1: leer el pedido de un mensaje pegado, lo dictado de una llamada o una foto ── */
async function leerPedidoIA(texto,img,C,tiendas){
  const catN=Object.fromEntries(C.cats.map(c=>[c.id,c.nom]));
  const cat=C.prods.map(p=>p.id+" | "+p.nombre+" | "+(catN[p.cat]||p.cat)).join("\n");
  const tl=tiendas.slice(0,300).map(t=>t.id+" | "+(t.codigo||"—")+" | "+t.nombre+" | "+(t.dueno||"—")+" | "+(t.tel||"—")).join("\n");
  const ap=(tiendas.length===1&&tiendas[0].apodos&&typeof tiendas[0].apodos==="object")?Object.keys(tiendas[0].apodos).slice(0,150).map(k=>k+" = "+tiendas[0].apodos[k]).join("\n"):"";
  const instr="Hoy es "+DIA_NOM[diaIdx()]+" "+hoy()+" (Perú).\n\nCATÁLOGO (id | nombre | categoría):\n"+cat
    +"\n\nTIENDAS (id | código | nombre | dueño | teléfono):\n"+tl+(ap?("\n\nAPODOS DE ESTA TIENDA (texto = id):\n"+ap):"")
    +"\n\n"+(img?("El pedido está en la imagen."+(texto?("\nNota del dueño: "+texto):"")):("MENSAJE:\n\"\"\"\n"+texto+"\n\"\"\""))
    +"\n\nDevuelve SOLO este JSON:\n{\"tienda_id\": número o null, \"tienda_texto\": \"cómo nombran a la tienda\", \"fecha\": \"AAAA-MM-DD\" o null, \"visita\": true o false, \"lineas\": [{\"texto\": \"lo que decía esa línea\", \"id\": \"id del catálogo\" o null, \"c\": cantidad}], \"nota\": \"indicaciones que no son productos\", \"dudas\": \"lo que no quedó claro\"}";
  const sys="Lees pedidos de tiendas para una distribuidora de panes y pasteles de Perú. Usa solo ids del catálogo y de la lista de tiendas. Si no estás seguro de un producto, pon id null: no adivines. Cantidades en unidades (docena = 12, media docena = 6). Si piden que pase el camión sin decir productos, visita = true. Si no dicen para cuándo, fecha = null. Las fechas relativas («mañana», «el jueves») se calculan desde hoy. Responde solo con el JSON.";
  const content=img?[{type:"image",source:{type:"base64",media_type:img[1],data:img[2]}},{type:"text",text:instr}]:instr;
  const r=await anthropic.messages.create({model:img?MODELO_IA_FOTOS:MODELO_IA_PEDIDOS,max_tokens:1500,system:sys,messages:[{role:"user",content}]});
  const txt=(r&&r.content||[]).map(c=>c.text||"").join("");
  const j=JSON.parse((txt.match(/\{[\s\S]*\}/)||["{}"])[0]);
  const f=fechaOK(j.fecha)?String(j.fecha):null;
  return {tienda_id:num(j.tienda_id,0,1e12,0)||null,tienda_texto:limpia(j.tienda_texto,80),fecha:f,lo_antes:!f,visita:j.visita===true,
    lineas:(Array.isArray(j.lineas)?j.lineas:[]).slice(0,60).filter(l=>l&&typeof l==="object").map(l=>({texto:limpia(l.texto,60),id:(l.id&&C.por[l.id])?String(l.id):null,c:Math.max(1,Math.round(num(l.c,1,999,1)))})),
    nota:limpia(j.nota,200),dudas:limpia(j.dudas,200)};
}
/* sin IA (o si la IA falla): lectura simple, línea por línea. Siempre se revisa. */
const NUMS_TXT={un:1,uno:1,una:1,dos:2,tres:3,cuatro:4,cinco:5,seis:6,siete:7,ocho:8,nueve:9,diez:10,once:11,doce:12,quince:15,veinte:20,treinta:30,cuarenta:40,cincuenta:50};
const RELLENO_RE=/\b(de|del|la|las|los|el|unidades?|und|uds?|paquetes?|bolsas?|por favor|porfa|porfavor|quiero|queremos|necesito|necesitamos|mandame|manda|mande|traeme|trae|traer|para|hola|buenos? dias|buenas tardes|buenas noches|buenas|gracias|me|nos|pedido|pedir|tambien|mas|manana|hoy|pasado|lunes|martes|miercoles|jueves|viernes|sabado|domingo|porfis|soy|somos|tienda)\b/g;
/* clave de un apodo: el texto sin cantidades ni relleno («10 chocos» y «5 chocos» son lo mismo) */
function claveApodo(t){
  let s=" "+normTxt(t)+" ";
  s=s.replace(/ \d+ /g," ").replace(/ (media|docenas?|un|una|uno|dos|tres|cuatro|cinco|seis|siete|ocho|nueve|diez|once|doce|quince|veinte|treinta|cuarenta|cincuenta) /g," ");
  return s.replace(RELLENO_RE," ").replace(/\s+/g," ").trim().slice(0,40);
}
function leerPedidoSimple(texto,C,tiendas){
  const T0=normTxt(texto);let tienda=null;
  const cod=String(texto).toUpperCase().match(/\b[A-Z]{3}-[A-Z]{3}-\d{4}\b/);
  if(cod)tienda=tiendas.find(t=>t.codigo===cod[0])||null;
  if(!tienda){const tels=(String(texto).match(/9\d{2}[\s-]?\d{3}[\s-]?\d{3}/g)||[]).map(x=>x.replace(/\D/g,""));
    if(tels.length)tienda=tiendas.find(t=>tels.some(x=>String(t.tel||"").replace(/\D/g,"").endsWith(x)))||null;}
  if(!tienda){let mejor=null;tiendas.forEach(t=>{const n=normTxt(t.nombre);if(n.length>=3&&(" "+T0+" ").includes(" "+n+" ")&&(!mejor||n.length>normTxt(mejor.nombre).length))mejor=t;});tienda=mejor;}
  if(!tienda&&tiendas.length===1)tienda=tiendas[0];
  const ap=(tienda&&tienda.apodos&&typeof tienda.apodos==="object")?tienda.apodos:{};
  const prods=C.prods.map(p=>({p,n:normTxt(p.nombre)})).filter(x=>x.n).sort((a,b)=>b.n.length-a.n.length);
  const sinS=s=>s.split(" ").map(w=>w.length>3?w.replace(/(es|s)$/,""):w).join(" ");
  const busca=s=>{
    const ka=claveApodo(s);if(ap[ka]&&C.por[ap[ka]])return ap[ka];
    let f=prods.find(x=>s===x.n||(" "+s+" ").includes(" "+x.n+" ")||(x.n.startsWith(s)&&s.length>=4));
    if(!f){const s2=sinS(s);f=prods.find(x=>{const n2=sinS(x.n);return s2===n2||(" "+s2+" ").includes(" "+n2+" ")||(n2.startsWith(s2)&&s2.length>=4)||(n2.includes(s2)&&s2.length>=5);});}
    return f?f.p.id:null;};
  const lineas=[];
  String(texto).replace(/\b[A-Z]{3}-[A-Z]{3}-\d{4}\b/gi," ").replace(/9\d{2}[\s-]?\d{3}[\s-]?\d{3}/g," ").split(/\n|,|;|\+|\s+y\s+/i).forEach(seg=>{
    let s=" "+normTxt(seg)+" ";if(!s.trim())return;
    let c=null;
    const toma=(re,val)=>{if(c!=null)return;const m=s.match(re);if(m){c=(typeof val==="function")?val(m):val;s=s.replace(m[0]," ");}};
    toma(/ media docena /,6);
    toma(/ (\d{1,3}) docenas? /,m=>Number(m[1])*12);
    toma(/ (?:un|una) docena /,12);
    toma(/ docenas? /,12);
    toma(/ (\d{1,3}) /,m=>Number(m[1]));
    Object.keys(NUMS_TXT).forEach(w=>toma(new RegExp(" "+w+" "),NUMS_TXT[w]));
    s=s.replace(RELLENO_RE," ").replace(/\s+/g," ").trim();
    if(c==null||s.length<3)return;
    lineas.push({texto:limpia(seg.trim(),60),id:busca(s),c:Math.max(1,Math.min(999,c))});
  });
  const visita=!lineas.length&&/\b(pase|pasen|venga|vengan|camion|carro|visita)\b/.test(T0);
  let fecha=null;
  if(/\bpasado manana\b/.test(T0))fecha=sumarDias(hoy(),2);
  else if(/\bmanana\b/.test(T0)&&!/\b(en|por|de) la manana\b/.test(T0))fecha=sumarDias(hoy(),1);
  else{const dias=["lunes","martes","miercoles","jueves","viernes","sabado","domingo"];const i=dias.findIndex(d=>new RegExp("\\b"+d+"\\b").test(T0));
    if(i>=0){let k=(i-diaIdx()+7)%7;if(k===0)k=7;fecha=sumarDias(hoy(),k);}}
  return {tienda_id:tienda?tienda.id:null,tienda_texto:tienda?tienda.nombre:"",fecha,lo_antes:!fecha,visita,lineas,nota:"",dudas:"Lectura simple, sin IA: revisa cada línea antes de confirmar."};
}
/* pasado su día, el pedido queda atrasado (sigue vigente) y avisa una vez en la Bandeja */
async function revisarAtrasados(){
  try{
    const{data:ps}=await db.from("pedidos").select("*").in("estado",PED_VIG).lt("fecha",hoy());
    const pend=(ps||[]).filter(p=>!p.avisado_atraso);
    if(!pend.length)return 0;
    const{data:cs}=await db.from("conductores").select("usuario,nombre");
    const N={};(cs||[]).forEach(c=>{N[c.usuario]=c.nombre||c.usuario;});
    for(const p of pend){
      await db.from("pedidos").update({avisado_atraso:true}).eq("id",p.id);
      await evento("pedido_atrasado","⏰ Pedidos atrasados","«"+(p.tienda||"")+"» pidió para "+fechaTxt(p.fecha)+" y aún no se entrega"
        +(p.conductor?(" (asignado a "+(N[p.conductor]||p.conductor)+")"):(p.estado==="devuelto"?" (devuelto: falta reasignarlo)":""))+": "+txtItems(p.items,p.visita)+". Sigue vigente.",String(p.id));
    }
    return pend.length;
  }catch(e){console.log("atrasados:",e.message);return 0;}
}
setTimeout(()=>{asegurarCodigos().then(n=>{if(n)console.log("Códigos: "+n+" tiendas recibieron su código");});revisarAtrasados();},12000);
setInterval(()=>{asegurarCodigos();revisarAtrasados();},10*60*1000);

/* ═══ 185 · FASE 5: TRASPASOS CON PRECIO Y PAGO ═══
   · De quién es la mercadería y el dinero: el empleado y el almacén son del dueño; el
     independiente, suyo. Entre dueños distintos («cruce») el que entrega pone precio
     (a costo PEPS, a precio o libre) y forma de pago (contado, Yape o fiado).
   · Pasos: pedir u ofrecer → el otro acepta (y pone precio si entrega) → si es fiado de
     mercadería del dueño a un independiente, lo aprueba el dueño → se entregan en persona y
     cada uno confirma → con las dos confirmaciones se mueven la mercadería y el dinero.
   · La venta del que entrega queda como venta suya (con su costo PEPS); el que recibe la
     toma a ese precio como costo. El fiado va a las cuentas entre conductores. */
const TR_ACT=["pendiente","parcial","aceptado","por_aprobar"];
async function duenoDe(u){if(!u||u==="almacen")return "dueno";return (await independientes()).has(u)?u:"dueno";}
async function nombresTr(){const N=await nombresAcreedores();N.almacen="Almacén";return N;}
const r2=v=>Math.round(Number(v||0)*100)/100;
/* costo PEPS promedio de las próximas q unidades de cada producto (lo que costaría entregarlas) */
async function costoPEPS(u,prods){
  const ids=Object.keys(prods||{});if(!ids.length)return {};
  const[{data:ls},R]=await Promise.all([db.from("lotes").select("prod_id,cant,costo,creado,id").eq("conductor",u).in("prod_id",ids),costoRef(ids,u)]);
  const lot=(ls||[]).filter(l=>Number(l.cant)>0).sort((a,b)=>(new Date(a.creado)-new Date(b.creado))||(a.id-b.id));
  const out={};
  ids.forEach(id=>{let q=Number(prods[id]||0),v=0,n=q;if(!(q>0)){out[id]=r2(R[id]);return;}
    for(const l of lot){if(q<=0)break;if(l.prod_id!==id)continue;const x=Math.min(q,Number(l.cant));v+=x*Number(l.costo||0);q-=x;}
    if(q>0)v+=q*Number(R[id]||0);out[id]=r2(v/n);});
  return out;
}
/* precio sugerido: el del catálogo para el tipo de tienda principal */
async function precioSugerido(ids){
  if(!ids.length)return {};
  const[{data:cat},{data:cats},P]=await Promise.all([db.from("catalogo").select("id,cat,precio,precios").in("id",ids),db.from("categorias").select("id,precio"),getParams()]);
  const tipo=(Array.isArray(P.tipos_tienda)&&P.tipos_tienda[0])||"bodega",cp={};(cats||[]).forEach(c=>{cp[c.id]=Number(c.precio||0);});
  const out={};(cat||[]).forEach(p=>{const pr=(p.precios&&typeof p.precios==="object")?p.precios:{};out[p.id]=r2(Number(pr[tipo])>0?pr[tipo]:(Number(p.precio)>0?p.precio:(cp[p.cat]||0)));});
  return out;
}
/* precios del traspaso según el modo (a costo: PEPS de quien entrega; a precio o libre: lo que pusieron) */
async function preciosTr(de,prods,modo,dados){
  const ids=Object.keys(prods);
  if(!["costo","precio","libre"].includes(modo))throw new Error("Elige el precio: a costo, a precio o libre");
  let pr={};
  if(modo==="costo")pr=await costoPEPS(de,prods);
  else{const sug=modo==="precio"?await precioSugerido(ids):{};
    ids.forEach(id=>{const v=num(dados&&dados[id],0,100000,0);pr[id]=r2(v>0?v:(sug[id]||0));});}
  const falta=ids.filter(id=>!(pr[id]>0));
  if(falta.length&&modo!=="costo")throw new Error("Falta el precio de "+falta.length+" producto(s)");
  const total=r2(ids.reduce((a,id)=>a+Number(prods[id])*Number(pr[id]||0),0));
  return {precios:pr,total};
}
/* ¿tiene quien entrega lo que se va a entregar? */
async function faltaStock(u,prods){
  const st=await leerStock(u),{data:cat}=await db.from("catalogo").select("id,nombre").in("id",Object.keys(prods));
  const nom={};(cat||[]).forEach(p=>{nom[p.id]=p.nombre;});
  const f=Object.keys(prods).filter(id=>Number(st.prods[id]||0)<Number(prods[id])).map(id=>(nom[id]||id)+" (tiene "+Number(st.prods[id]||0)+", van "+prods[id]+")");
  return f.length?f.join(", "):"";
}
const PAGO_TXT={efectivo:"al contado",yape:"por Yape",fiado:"fiado"};
function textoTr(t,N){
  const n=u=>N[u]||(u==="almacen"?"Almacén":u);
  return n(t.de)+" → "+n(t.para)+(t.total!=null&&t.pago?(" · S/"+Number(t.total).toFixed(2)+" "+(PAGO_TXT[t.pago]||t.pago)):"");
}
/* cuentas entre conductores: cargos (fiado) y abonos (cobros y pagos), sin los anulados */
async function cuentasPares(filtro){
  const{data}=await db.from("cuentas_mov").select("*").order("id",{ascending:true});
  const movs=(data||[]).filter(m=>!m.anulado&&(!filtro||filtro(m)));
  const P={};
  movs.forEach(m=>{const k=m.deudor+"|"+m.acreedor,c=P[k]||(P[k]={deudor:m.deudor,acreedor:m.acreedor,cargos:[],saldo:0,a_favor:0});
    const monto=Number(m.monto||0);
    if(m.tipo==="cargo"){c.cargos.push({id:m.id,fecha:m.creado,detalle:m.detalle,monto,pagado:0,pendiente:monto,cobros:[],traspaso_id:m.traspaso_id||null});return;}
    let resto=monto;
    for(const g of c.cargos){if(resto<=0)break;if(g.pendiente<=0)continue;const x=Math.min(resto,g.pendiente);g.pagado=r2(g.pagado+x);g.pendiente=r2(g.pendiente-x);g.cobros.push({por:m.por,fecha:m.creado,monto:r2(x),pago:m.pago||null});resto-=x;}
    if(resto>0.004)c.a_favor=r2(c.a_favor+resto);
  });
  return Object.values(P).map(c=>{c.saldo=r2(c.cargos.reduce((a,g)=>a+g.pendiente,0));c.cargos.forEach(g=>{g.estado=g.pendiente<=0.004?"pagado":(g.pagado>0?"parcial":"pendiente");});return c;});
}
async function saldoPar(deudor,acreedor){const cs=await cuentasPares(m=>m.deudor===deudor&&m.acreedor===acreedor);return cs.length?cs[0].saldo:0;}
/* dinero de traspasos y cuentas que pasa por las manos de un conductor en su viaje.
   Empleado: lo que él cobró o pagó por el dueño. Independiente: todo lo que le pagaron o pagó
   (lo registre quien lo registre), porque es su plata. */
async function dineroTr(u,inicio,fin){
  const[{data:trs},{data:cm}]=await Promise.all([
    db.from("traspasos").select("id,de,para,total,pago,estado,cruce,creado").eq("para",u).eq("estado","completado").gte("creado",inicio),
    db.from("cuentas_mov").select("*").eq("tipo","abono").gte("creado",inicio)]);
  const yo=await duenoDe(u),ind=yo===u;
  const en=x=>!fin||new Date(x.creado)<=new Date(fin);
  const compras=(trs||[]).filter(t=>t.cruce&&t.pago==="efectivo"&&en(t)).reduce((a,t)=>a+Number(t.total||0),0);
  const mov=(cm||[]).filter(m=>!m.anulado&&(m.pago||"efectivo")==="efectivo"&&en(m)&&(ind?(m.deudor===u||m.acreedor===u):m.por===u));
  const cobros=mov.filter(m=>m.acreedor===yo).reduce((a,m)=>a+Number(m.monto||0),0);
  const pagos=mov.filter(m=>m.deudor===yo).reduce((a,m)=>a+Number(m.monto||0),0);
  return {compras:r2(compras),cobros:r2(cobros),pagos:r2(pagos),neto:r2(cobros-pagos-compras)};
}
/* completar: moverla mercadería (y el dinero) cuando los dos confirmaron */
async function completarTraspaso(t,N){
  const pr=limpiaProds(t.prods);
  if(t.cruce&&t.de!=="almacen"){const f=await faltaStock(t.de,pr);if(f)return {ok:false,error:"A quien entrega ya no le alcanza: "+f+". Revisen y vuelvan a confirmar."};}
  if(t.cruce&&t.de==="almacen"){const f=await faltaStock("almacen",pr);if(f)return {ok:false,error:"En el almacén no alcanza: "+f};}
  const menos={},mas={};Object.keys(pr).forEach(id=>{menos[id]=-pr[id];mas[id]=pr[id];});
  let sal={costo:0,capas:{}};
  if(Object.keys(pr).length){
    sal=await moverStock(t.de,menos,"traspaso_envia",t.id);
    await moverStock(t.para,mas,"traspaso_recibe",t.id,t.cruce?{costos:t.precios||{}}:{capas:sal.capas});
  }
  const upd={estado:"completado"};
  if(t.cruce){
    const{data:cat}=await db.from("catalogo").select("id,nombre").in("id",Object.keys(pr).length?Object.keys(pr):["-"]);
    const nom={};(cat||[]).forEach(p=>{nom[p.id]=p.nombre;});
    const its=Object.keys(pr).map(id=>({id,n:nom[id]||id,c:pr[id],pu:Number((t.precios||{})[id]||0)}));
    const total=r2(t.total),fiado=t.pago==="fiado";
    const{data:v}=await db.from("ventas").insert({tienda_id:null,tienda:"↔ Traspaso a "+(N[t.para]||t.para),conductor:t.de,items:its,total,
      metodo:fiado?"credito":(t.pago==="yape"?"yape":"efectivo"),efectivo:t.pago==="efectivo"?total:0,credito:fiado?total:0,abono:0,
      resumen:its.map(x=>x.n+" x"+x.c).join(", "),costo:r2(sal.costo),uid:"tr-"+t.id,traspaso_id:t.id}).select().single();
    if(v)upd.venta_id=v.id;
    if(fiado&&total>0){
      const deudor=await duenoDe(t.para),acreedor=await duenoDe(t.de);
      await db.from("cuentas_mov").insert({deudor,acreedor,tipo:"cargo",monto:total,detalle:"Traspaso #"+t.id+": "+its.map(x=>x.c+" "+x.n).join(", "),por:t.de,traspaso_id:t.id});
    }
  }
  /* se confirmaron lejos el uno del otro → aviso */
  if(t.pos_de&&t.pos_para&&t.pos_de.lat!=null&&t.pos_para.lat!=null){
    const d=metrosEntre(Number(t.pos_de.lat),Number(t.pos_de.lon),Number(t.pos_para.lat),Number(t.pos_para.lon));upd.dist_m=d;
    if(d>200)await evento("traspaso_lejos","📍 Traspaso confirmado lejos",textoTr(t,N)+": confirmaron a "+d+" m el uno del otro (más de 200 m). Revisa si de verdad se entregaron en persona.",String(t.id));
  }
  await db.from("traspasos").update(upd).eq("id",t.id);
  Object.assign(t,upd);
  const det=Object.keys(pr).map(id=>id+"×"+pr[id]).join(", ");
  if(t.de==="almacen")await db.from("kardex").insert({conductor:"almacen",tipo:"almacen_salida",detalle:JSON.stringify(t.items)+" · entregado a "+t.para});
  if(t.para==="almacen")await db.from("kardex").insert({conductor:"almacen",tipo:"almacen_retorno",detalle:JSON.stringify(t.items)+" · recibido de "+t.de});
  await db.from("kardex").insert({conductor:t.para,tipo:"traspaso_in",detalle:"De "+(N[t.de]||t.de)+": "+det+(t.cruce?(" · S/"+Number(t.total).toFixed(2)+" "+(PAGO_TXT[t.pago]||"")):"")});
  await db.from("kardex").insert({conductor:t.de,tipo:"traspaso_out",detalle:"Hacia "+(N[t.para]||t.para)+": "+det+(t.cruce?(" · S/"+Number(t.total).toFixed(2)+" "+(PAGO_TXT[t.pago]||"")):"")});
  if(t.de!=="almacen")await avisoA(t.de,"✓ Traspaso completado con "+(N[t.para]||t.para)+": ambos confirmaron.");
  if(t.para!=="almacen")await avisoA(t.para,"✓ Traspaso completado con "+(N[t.de]||t.de)+": ambos confirmaron. Ya está en tu carga.");
  await evento("traspaso","↔ Traspaso completado",textoTr(t,N)+" — confirmado por ambos.",String(t.id));
  return {ok:true};
}

/* 183 · los números del dueño nunca incluyen a los independientes */
let INDEP={t:0,s:new Set()};
async function independientes(){
  if(Date.now()-INDEP.t<30000)return INDEP.s;
  const{data}=await db.from("conductores").select("usuario,tipo");
  INDEP={t:Date.now(),s:new Set((data||[]).filter(c=>tipoDe(c)==="independiente").map(c=>c.usuario))};
  return INDEP.s;
}
/* cambiar de tipo solo entre viajes */
async function enViaje(u){
  const[{data:st},{data:tr},{data:cg}]=await Promise.all([
    db.from("stock_conductor").select("cant").eq("conductor",u),
    db.from("traspasos").select("id").or(`de.eq.${u},para.eq.${u}`).in("estado",TR_ACT),
    db.from("cargas").select("id").eq("conductor",u).eq("estado","pendiente")]);
  const uni=(st||[]).reduce((a,x)=>a+Number(x.cant||0),0),m=[];
  if(uni>0)m.push("tiene "+uni+" unidades en su camión");
  if((tr||[]).length)m.push("tiene traspasos sin terminar");
  if((cg||[]).length)m.push("tiene una carga sin confirmar");
  return m.join(", ");
}
/* «es la misma»: la tienda pendiente pasa sus ventas, visitas, créditos y pedidos a la existente */
async function fusionarTienda(pid,did,por){
  const[{data:Pt},{data:Dt}]=await Promise.all([db.from("tiendas").select("*").eq("id",pid).maybeSingle(),db.from("tiendas").select("*").eq("id",did).maybeSingle()]);
  if(!Pt||!Dt)throw new Error("No encontré las dos tiendas");
  if(Number(Pt.id)===Number(Dt.id))throw new Error("Es la misma tienda");
  const mov={};
  for(const tb of ["ventas","visitas","creditos_mov","pedidos"]){
    const upd=(tb==="creditos_mov")?{tienda_id:Dt.id}:{tienda_id:Dt.id,tienda:Dt.nombre};
    const{data,error}=await db.from(tb).update(upd).eq("tienda_id",Pt.id).select("id");
    if(error)throw new Error("No se pudo pasar "+tb+": "+error.message);
    mov[tb]=(data||[]).length;
  }
  const upD={sa:await saldoHistorial(Dt.id)};
  const hab=Array.isArray(Dt.habilitados)?Dt.habilitados.slice():[];
  if(Pt.conductor_reg&&Pt.conductor_reg!=="admin"&&!hab.includes(Pt.conductor_reg)){hab.push(Pt.conductor_reg);upD.habilitados=hab;}
  const{error:e1}=await db.from("tiendas").update(upD).eq("id",Dt.id);if(e1)throw new Error(e1.message);
  await db.from("tiendas").update({act:false,estado_reg:"fusionada",posible_dup:Dt.id,sa:0,notas:limpia("Unida con #"+Dt.id+" "+Dt.nombre+(Pt.notas?" · "+Pt.notas:""),200)}).eq("id",Pt.id);
  await db.from("logs").insert({tipo:"tienda",detalle:"#"+Dt.id+" "+Dt.nombre+" · recibió lo de #"+Pt.id+" "+Pt.nombre+" (repetida): "+mov.ventas+" ventas, "+mov.visitas+" visitas, "+mov.creditos_mov+" movimientos de crédito, "+mov.pedidos+" pedidos · "+por});
  return {mov,destino:Dt,origen:Pt};
}
// ═══ SIRVE LAS APPS DESDE EL MISMO SERVIDOR (sin Netlify) ═══
function sirve(archivo){
  return (req,res)=>{
    const p=path.join(__dirname,archivo);
    fs.readFile(p,"utf8",(err,html)=>{
      if(err)return res.status(404).send("Falta el archivo "+archivo+" en el repositorio.");
      res.set("Cache-Control","no-store");
      res.type("html").send(html);
    });
  };
}
app.get(["/favicon.ico","/favicon.png","/apple-touch-icon.png","/apple-touch-icon-precomposed.png"],(req,res)=>res.status(204).end());
app.get(["/app","/app.html","/conductor"],sirve("app-conductor.html"));
app.get(["/panel","/panel.html","/admin"],sirve("admin-dashboard.html"));
app.get("/",(req,res)=>res.type("html").send('<meta charset="utf-8"><div style="font-family:system-ui;padding:40px;line-height:2"><h3>Distribuidora — sistema</h3><a href="/app">📱 App del conductor</a><br><a href="/panel">🖥️ Panel del dueño</a></div>'));
app.get("/version",(req,res)=>{
  const marcas={
    "app-conductor.html":["v5no304","v5origen","v5notipos","v5stockp","cpGetPrecio(cat.id,p.id)",
      "onclick=\"abrirMerma()\"","v5botones","v5ritmo","window.repoT","window.nivelApp",
      "v5ciclo","abrirPropCiclo","window.RT_RITMO",
      "v5botones2","v5dias","window.centrarRegT","window.RT_DIAS","en-tiendas",
      "v5salida","cerrarMenuAbierto",
      "v5arreglos169","window.anotaRechazo","v5fingidas","window.enviarOp","id=\"tr3-est\"",
      "v5precioamano","window.posFresca=posFresca","v5lugares181","v5indep183","v5pedidos184","v5traspasos185","window.BUILD='2026-09-24-D'"],
    "admin-dashboard.html":["v5sinprestamo","v5pdprecios","v5dupids","v5catipo",
      "v5almmover","window.pkTipo","pkEtiqueta(p)","v5ritmo2","v5ritmocfg","window.repTP","window.nivelP",
      "v5ciclofiltro","window.TDS","window.EVENTOS=r.eventos","ritmo_sugerido",
      "v5diasP","v5diascfg","window.AT_DIAS","dias_sugeridos",
      "v5salidaP","salirDeTodo","function stDe(p)","cerrarEdicion()\" style=\"background:none\">Cerrar sin guardar",
      "v5arreglos176","window.pintaWA","window.ALM={stock:{},prods:[],movimientos:[]}","var _ir=window.ir;",
      "v5picker179","window.pintaCatCosto","v5catcosto179","v5lugares181","v5indep183","v5pedidos184","v5traspasos185"]
  };
  const out={servidor:{bloque:185,pedidos:{ia:!!anthropic,modelo_texto:MODELO_IA_PEDIDOS,modelo_fotos:MODELO_IA_FOTOS},lugares:(()=>{const G=geo();return G.falta?"FALTA distritos-peru.json":(G.dist.length+" distritos")})(),etag_desactivado:app.get("etag")===false,consultas_en_paralelo:true,hora:new Date().toISOString()},archivos:{}};
  Object.keys(marcas).forEach(f=>{
    try{
      const txt=fs.readFileSync(path.join(__dirname,f),"utf8");
      const faltan=marcas[f].filter(m=>txt.indexOf(m)<0);
      const mb=txt.match(/window\.BUILD='([^']+)'/);
      out.archivos[f]={kb:Math.round(txt.length/1024),
        al_dia:faltan.length===0,
        build_del_servidor:mb?mb[1]:undefined,
        build_del_telefono:(f==="app-conductor.html"&&req.query.build)?String(req.query.build).slice(0,30):undefined,
        telefono_al_dia:(f==="app-conductor.html"&&req.query.build&&mb)?(String(req.query.build)===mb[1]):undefined,
        faltan:faltan.length?faltan:undefined};
    }catch(e){out.archivos[f]={error:"no está en el repositorio"};}
  });
  res.set("Cache-Control","no-store").json(out);
});
// ═══ STOCK DEL CAMIÓN EN LA BASE ═══
// Fuente de verdad del inventario de cada conductor. El teléfono guarda su
// propia copia para trabajar sin señal, pero al reconectar manda lo pendiente
// y vuelve a leer de aquí.
/* 183 · COSTO PEPS POR LOTES. Cada entrada de mercadería (carga, traspaso, sobrante…) crea
   un lote con su costo; cada salida (venta, merma, traspaso…) consume primero los lotes más
   viejos. Así cada venta sabe cuánto costó lo vendido (ventas.costo). Si faltan lotes (stock
   de antes de este cambio), lo que falta se valoriza con el costo de referencia. */
async function costoRef(ids,conductor){
  const[{data:cat},Pp,{data:c}]=await Promise.all([
    db.from("catalogo").select("id,cat,costo").in("id",ids),getParams(),
    (conductor&&conductor!=="almacen")?db.from("conductores").select("tipo,costos").eq("usuario",conductor).maybeSingle():Promise.resolve({data:null})]);
  const cc=(Pp&&Pp.costos)||{},mio=(c&&tipoDe(c)==="independiente"&&c.costos&&typeof c.costos==="object")?c.costos:{};
  const r={};
  (cat||[]).forEach(p=>{r[p.id]=Number(mio[p.id])>0?Number(mio[p.id]):(Number(p.costo)>0?Number(p.costo):num(cc[p.cat],0,100000,0));});
  ids.forEach(id=>{if(r[id]==null)r[id]=0;});
  return r;
}
async function moverStock(conductor,cambios,motivo,ref,opt){
  if(!conductor||!cambios||!Object.keys(cambios).length)return {costo:0,capas:{}};
  const ids=Object.keys(cambios).slice(0,300);
  const{data:act}=await db.from("stock_conductor").select("prod_id,cant,base").eq("conductor",conductor).in("prod_id",ids);
  const ahora={};(act||[]).forEach(r=>ahora[r.prod_id]={cant:Number(r.cant||0),base:Number(r.base||0)});
  const filas=[],movs=[];
  ids.forEach(id=>{
    const d=num(cambios[id],-99999,99999);
    if(!d)return;
    const prev=ahora[id]||{cant:0,base:0};
    const nueva=Math.max(0,prev.cant+d);
    filas.push({conductor,prod_id:id,cant:nueva,
      base:(motivo==="carga")?(prev.base+d):prev.base,
      actualizado:new Date().toISOString()});
    movs.push({conductor,prod_id:id,delta:d,motivo:motivo||"ajuste",ref:ref?String(ref).slice(0,40):null});
  });
  if(filas.length)await db.from("stock_conductor").upsert(filas);
  if(movs.length)await db.from("stock_mov").insert(movs);
  const out={costo:0,capas:{}};
  try{
    let R=null;const refC=async()=>{if(!R)R=await costoRef(ids,conductor);return R;};
    const refTxt=ref?String(ref).slice(0,40):null,nuevos=[];
    const pos=ids.filter(id=>num(cambios[id],-99999,99999)>0),neg=ids.filter(id=>num(cambios[id],-99999,99999)<0);
    for(const id of pos){
      let q=num(cambios[id],0,99999);
      const cin=opt&&opt.capas&&Array.isArray(opt.capas[id])?opt.capas[id]:null;
      if(cin)for(const k of cin){const x=Math.min(q,Number(k.cant||0));if(x>0){nuevos.push({conductor,prod_id:id,cant:x,cant_ini:x,costo:Number(k.costo||0),origen:motivo||"ajuste",ref:refTxt});q-=x;}}
      if(q>0){const cu=(opt&&opt.costos&&opt.costos[id]!=null&&Number(opt.costos[id])>0)?Number(opt.costos[id]):(await refC())[id];
        nuevos.push({conductor,prod_id:id,cant:q,cant_ini:q,costo:cu,origen:motivo||"ajuste",ref:refTxt});}
    }
    if(nuevos.length)await db.from("lotes").insert(nuevos);
    if(neg.length){
      const{data:ls}=await db.from("lotes").select("*").eq("conductor",conductor).in("prod_id",neg);
      const lot=(ls||[]).filter(l=>Number(l.cant)>0).sort((a,b)=>(new Date(a.creado)-new Date(b.creado))||(a.id-b.id));
      for(const id of neg){
        let q=-num(cambios[id],-99999,0);const cap=[];
        for(const l of lot){if(q<=0)break;if(l.prod_id!==id||Number(l.cant)<=0)continue;
          const x=Math.min(q,Number(l.cant));l.cant=Math.round((Number(l.cant)-x)*1000)/1000;q=Math.round((q-x)*1000)/1000;
          cap.push({cant:x,costo:Number(l.costo||0)});await db.from("lotes").update({cant:l.cant}).eq("id",l.id);}
        if(q>0)cap.push({cant:q,costo:(await refC())[id]});
        out.capas[id]=cap;out.costo+=cap.reduce((a,k)=>a+k.cant*k.costo,0);
      }
      out.costo=Math.round(out.costo*100)/100;
    }
  }catch(e){console.log("lotes:",e.message);}
  return out;
}
/* 183 · valor al costo de lo que tiene alguien (lotes vivos; lo que no tiene lote, a referencia) */
async function valorStock(conductor){
  const st=await leerStock(conductor),ids=Object.keys(st.prods);
  if(!ids.length)return {prods:{},valor:0,det:[]};
  const[{data:ls},R,{data:cat}]=await Promise.all([db.from("lotes").select("prod_id,cant,costo").eq("conductor",conductor).in("prod_id",ids),costoRef(ids,conductor),db.from("catalogo").select("id,nombre").in("id",ids)]);
  const nom={};(cat||[]).forEach(p=>nom[p.id]=p.nombre);
  let valor=0;const det=[];
  ids.forEach(id=>{
    let q=Number(st.prods[id]||0),v=0;
    (ls||[]).filter(l=>l.prod_id===id&&Number(l.cant)>0).forEach(l=>{const x=Math.min(q,Number(l.cant));v+=x*Number(l.costo||0);q-=x;});
    if(q>0)v+=q*R[id];
    v=Math.round(v*100)/100;valor+=v;det.push({id,n:nom[id]||id,cant:Number(st.prods[id]||0),valor:v});
  });
  return {prods:st.prods,valor:Math.round(valor*100)/100,det};
}
async function leerStock(conductor){
  const{data}=await db.from("stock_conductor").select("prod_id,cant,base").eq("conductor",conductor);
  const prods={},base={};
  (data||[]).forEach(r=>{if(Number(r.cant)!==0||Number(r.base)!==0){prods[r.prod_id]=Number(r.cant||0);base[r.prod_id]=Number(r.base||0);}});
  return{prods,base};
}
function limpiaProds(o){
  const r={};
  Object.keys((o&&typeof o==="object")?o:{}).slice(0,300).forEach(k=>{
    const id=limpia(k,20),v=num(o[k],0,9999);
    if(id&&v)r[id]=v;
  });
  return r;
}
async function porCategoria(prods){
  const ids=Object.keys(prods||{});
  if(!ids.length)return{};
  const{data}=await db.from("catalogo").select("id,cat").in("id",ids);
  const cat={};(data||[]).forEach(p=>cat[p.id]=p.cat);
  const r={};ids.forEach(id=>{const k=cat[id]||"—";r[k]=(r[k]||0)+Number(prods[id]||0)});
  return r;
}
app.post("/conductor/ubicacion",authC,async(req,res)=>{
  const lat=num(req.body.lat,-90,90),lon=num(req.body.lon,-180,180);
  if(!lat||!lon)return res.status(400).json({ok:false,error:"Sin coordenadas"});
  await db.from("conductores").update({lat_cel:lat,lon_cel:lon,cel_hora:new Date().toISOString()}).eq("usuario",req.cond.u);
  res.json({ok:true});
});
app.get("/conductor/almacen",authC,async(req,res)=>{
  res.set("Cache-Control","no-store");
  const s=await leerStock("almacen");
  const cats=await porCategoria(s.prods);
  const{data:cat}=await db.from("catalogo").select("id,nombre");
  const nom={};(cat||[]).forEach(p=>nom[p.id]=p.nombre);
  res.json({ok:true,por_categoria:cats,
    total:Object.keys(s.prods).reduce((a,k)=>a+Number(s.prods[k]||0),0),
    prods:Object.keys(s.prods).map(id=>({id,n:nom[id]||id,cant:Number(s.prods[id]||0)})).filter(x=>x.cant>0)});
});
app.get("/conductor/stock",authC,async(req,res)=>{
  res.set("Cache-Control","no-store");
  const s=await leerStock(req.cond.u);
  res.json({ok:true,prods:s.prods,base:s.base,por_categoria:await porCategoria(s.prods)});
});
/* 175 · se quitó POST /conductor/stock/ajuste: ninguna app lo usaba y dejaba al conductor cambiar su propio stock sin rastro */
app.get("/admin/stock",authA,async(req,res)=>{
  res.set("Cache-Control","no-store");
  const{data:us}=await db.from("conductores").select("usuario,nombre,activo,en_turno");
  const{data:st}=await db.from("stock_conductor").select("conductor,prod_id,cant,base,actualizado");
  const{data:cat}=await db.from("catalogo").select("id,cat,nombre");
  const nom={},cDe={};(cat||[]).forEach(p=>{nom[p.id]=p.nombre;cDe[p.id]=p.cat});
  const porCond={};
  (st||[]).forEach(r=>{
    if(Number(r.cant)<=0)return;
    const c0=porCond[r.conductor]||(porCond[r.conductor]={total:0,actualizado:null,cats:{},prods:[]});
    c0.total+=Number(r.cant);
    c0.prods.push({id:r.prod_id,n:nom[r.prod_id]||r.prod_id,cat:cDe[r.prod_id]||"—",cant:Number(r.cant),base:Number(r.base||0)});
    const k=cDe[r.prod_id]||"—";c0.cats[k]=(c0.cats[k]||0)+Number(r.cant);
    if(!c0.actualizado||r.actualizado>c0.actualizado)c0.actualizado=r.actualizado;
  });
  const alm=porCond["almacen"];
  res.json({ok:true,almacen:alm||{total:0,cats:{},prods:[],actualizado:null},
    conductores:(us||[]).filter(u=>u.activo).map(u=>({
    usuario:u.usuario,nombre:u.nombre,en_turno:!!u.en_turno,
    ...(porCond[u.usuario]||{total:0,cats:{},prods:[],actualizado:null})
  }))});
});
app.post("/admin/cerrar-viaje",authA,async(req,res)=>{
  const u=limpia(req.body.conductor,20);
  const nota=limpia(req.body.nota,300);
  if(!u)return res.status(400).json({ok:false,error:"Falta el conductor"});
  if(!nota||nota.length<5)return res.status(400).json({ok:false,error:"Escribe por qué cierras el viaje tú"});
  const{data:yo}=await db.from("conductores").select("turno_ini,nombre,en_turno").eq("usuario",u).maybeSingle();
  if(!yo||!yo.en_turno)return res.status(409).json({ok:false,error:"Ese conductor no tiene un viaje abierto"});

  const st=await leerStock(u);
  const quedan=Object.keys(st.prods).reduce((s,k)=>s+Number(st.prods[k]||0),0);
  const destino=String(req.body.stock_restante||"");   // "almacen" | "pendiente"
  if(quedan>0&&destino!=="almacen"&&destino!=="pendiente")
    return res.status(409).json({ok:false,motivo:"decidir_stock",quedan,
      por_categoria:await porCategoria(st.prods),
      error:"Quedan "+quedan+" unidades en el camión: decide si vuelven al almacén o quedan pendientes a cargo del conductor"});

  const inicio=yo.turno_ini||new Date(Date.now()-7*86400000).toISOString();
  const fin=new Date().toISOString();
  const [vts0,mov,trs,gas0,perd,ent0]=await Promise.all([
    db.from("ventas").select("*").eq("conductor",u).gte("creado",inicio).lte("creado",fin),
    db.from("stock_mov").select("motivo,delta").eq("conductor",u).gte("creado",inicio),
    db.from("traspasos").select("*").or("de.eq."+u+",para.eq."+u).gte("creado",inicio),
    db.from("gastos").select("id,categoria,monto,detalle,rechazado,creado").eq("conductor",u).gte("creado",inicio),
    db.from("perdidas").select("motivo,valor,costo,detalle,tienda,tipo,creado").eq("conductor",u).gte("creado",inicio),
    db.from("entregas").select("id,monto,estado,nota,creado").eq("conductor",u).gte("creado",inicio)
  ]).then(r=>r.map(x=>x.data||[]));
  /* 175 · fuera: ventas anuladas y gastos rechazados; se descuenta el efectivo ya entregado al dueño */
  const vts=vts0.filter(v=>!v.anulada),gas=gas0.filter(g=>!g.rechazado),ent=ent0.filter(e=>e.estado!=="rechazada");
  const entregas=Math.round(ent.reduce((s,e)=>s+Number(e.monto||0),0)*100)/100;
  const sum=(a,f)=>a.reduce((s,x)=>s+Number(f(x)||0),0);
  const efectivo=sum(vts,v=>v.metodo==="yape"?0:v.efectivo);
  const yape=sum(vts.filter(v=>v.metodo==="yape"),v=>v.total);
  const fiado=sum(vts,v=>v.credito), abonos=sum(vts,v=>v.abono);
  const gastos=sum(gas,g=>g.monto), perdidas=sum(perd,p=>p.valor);
  const mSum=(m)=>mov.filter(x=>x.motivo===m).reduce((s,x)=>s+Math.abs(Number(x.delta||0)),0);

  // el stock que quedaba: al almacén o pendiente a cargo del conductor
  if(quedan>0){
    const menos={};Object.keys(st.prods).forEach(id=>{menos[id]=-Number(st.prods[id]||0)});
    await moverStock(u,menos,destino==="almacen"?"cierre_devuelve":"cierre_pendiente",null);
    if(destino==="almacen"){
      const mas={};Object.keys(st.prods).forEach(id=>{mas[id]=Number(st.prods[id]||0)});
      await moverStock("almacen",mas,"cierre_recibe",null);
    }
  }
  const DT=await dineroTr(u,inicio,fin);   /* 185 */
  const resumen={
    conductor:u,nombre:yo.nombre||u,inicio,fin,
    dias:Math.max(1,Math.round((new Date(fin)-new Date(inicio))/86400000)),
    ventas:{n:vts.length,total:sum(vts,v=>v.total),efectivo,yape,fiado,abonos},
    efectivo_esperado:Math.round((efectivo+abonos-gastos-entregas+DT.neto)*100)/100,
    traspasos_dinero:DT,   /* 185 · cobros y pagos de cuentas, compras al contado a independientes */
    entregas:{total:entregas,n:ent.length,detalle:ent},
    gastos:{total:gastos,detalle:gas},
    perdidas:(function(){
      const m=perd.filter(p=>!/^ajuste/.test(p.tipo||"")),a=perd.filter(p=>p.tipo==="ajuste");   /* 177 · pendientes y rechazados fuera */
      return{total:m.reduce((s,p)=>s+Number(p.valor||0),0),
        costo:m.reduce((s,p)=>s+Number(p.costo||0),0),
        n:m.length,detalle:m,
        ajustes:{n:a.length,detalle:a},
        por_motivo:m.reduce((r,p)=>{r[p.motivo]=(r[p.motivo]||0)+Number(p.valor||0);return r},{})};
    })(),
    mercaderia:{cargado:mSum("carga"),recibido_en_ruta:mSum("traspaso_recibe"),
      vendido:mSum("venta"),devuelto:mSum("traspaso_envia"),queda:quedan,
      destino_restante:quedan?destino:null},
    traspasos:trs.map(t=>({id:t.id,de:t.de,para:t.para,estado:t.estado,items:t.items})),
    cerrado_por_dueno:true
  };
  const decl=num(req.body.efectivo_declarado,0,999999);
  const dif=Math.round((decl-resumen.efectivo_esperado)*100)/100;
  const MARG=num((await getParams()).margen_liq,0,1000,5);resumen.margen=MARG;resumen.dentro_margen=Math.abs(dif)<=MARG;
  const{data:l}=await db.from("liquidaciones").insert({
    conductor:u,dia:{},kx:[],inicio,fin,estado:"cerrada_por_dueno",
    efectivo_declarado:decl,diferencia:dif,resumen,
    nota:"Cerrado por el dueño: "+nota,confirmada_en:fin
  }).select().single();
  if(l)await db.from("ventas").update({liq_id:l.id}).eq("conductor",u).gte("creado",inicio).lte("creado",fin).is("liq_id",null);
  await db.from("conductores").update({en_turno:false,turno_hora:fin,turno_ini:null}).eq("usuario",u);
  await db.from("logs").insert({tipo:"turno",detalle:u+" termina (cerrado por el dueño: "+nota+")"});
  await avisoA(u,"El dueño cerró tu viaje. Motivo: "+nota+(quedan?("\nMercadería restante: "+quedan+" unidades "+(destino==="almacen"?"devueltas al almacén":"pendientes a tu cargo")):""));
  res.json({ok:true,id:l&&l.id,resumen,diferencia:dif});
});
// ══════════ GPS: consulta a la plataforma y refresco periódico ══════════
let GPS_ULTIMO_ERROR=null;
async function obtenerGPS(){
  if(!GPS_PLAT)return [];
  try{
    if(GPS_PLAT==="traccar"){
      const base=String(process.env.GPS_API_URL||"").replace(/\/+$/,"");
      const auth=Buffer.from(`${process.env.GPS_USER}:${process.env.GPS_PASSWORD}`).toString("base64");
      const r=await fetch(base+"/api/positions",{headers:{Authorization:`Basic ${auth}`}});
      if(!r.ok){GPS_ULTIMO_ERROR="Traccar respondió "+r.status;return [];}
      const d=await r.json();
      GPS_ULTIMO_ERROR=null;
      return (d||[]).map(p=>({gps_id:String(p.deviceId),lat:Number(p.latitude),lon:Number(p.longitude),
        vel:Number(p.speed||0),ts:p.fixTime||p.deviceTime||null}))
        .filter(p=>isFinite(p.lat)&&isFinite(p.lon));
    }
    if(GPS_PLAT==="wialon"){
      const base=process.env.GPS_API_URL||"https://hst-api.wialon.com/wialon/ajax.html";
      const lr=await fetch(`${base}?svc=token/login&params=${encodeURIComponent(JSON.stringify({token:process.env.GPS_API_KEY}))}`);
      const ld=await lr.json();
      if(!ld.eid){GPS_ULTIMO_ERROR="Wialon: login rechazado";return [];}
      const params={spec:{itemsType:"avl_unit",propName:"sys_name",propValueMask:"*",sortType:"sys_name"},force:1,flags:1025,from:0,to:0};
      const sr=await fetch(`${base}?svc=core/search_items&params=${encodeURIComponent(JSON.stringify(params))}&sid=${ld.eid}`);
      const sd=await sr.json();
      GPS_ULTIMO_ERROR=null;
      return (sd.items||[]).filter(x=>x.pos).map(x=>({gps_id:String(x.id),lat:x.pos.y,lon:x.pos.x,vel:x.pos.s||0,ts:x.pos.t?new Date(x.pos.t*1000).toISOString():null}));
    }
    GPS_ULTIMO_ERROR="Plataforma no soportada: "+GPS_PLAT;
    return [];
  }catch(e){GPS_ULTIMO_ERROR=e.message;console.error("GPS("+GPS_PLAT+"):",e.message);return [];}
}
// Refresco cada minuto: guarda la posición de cada conductor y su recorrido
const ULT_POS=new Map();
async function refrescarGPS(){
  if(!GPS_PLAT)return;
  const pos=await obtenerGPS();
  if(!pos.length)return;
  const{data:cs}=await db.from("conductores").select("usuario,gps_id").not("gps_id","is",null);
  const ahora=new Date().toISOString();
  for(const c of (cs||[])){
    const p=pos.find(x=>String(x.gps_id)===String(c.gps_id));
    if(!p)continue;
    await db.from("conductores").update({lat:p.lat,lon:p.lon,gps_fuente:GPS_PLAT,
      gps_hora:p.ts?new Date(p.ts).toISOString():ahora}).eq("usuario",c.usuario);
    /* 175 · con el camión parado se guardaba un punto por minuto (105 mil en un mes) */
    const u0=ULT_POS.get(c.usuario);
    const mov=!u0||Math.hypot((p.lat-u0.lat)*111000,(p.lon-u0.lon)*107000)>15;
    if(mov||(Date.now()-u0.t)>10*60000){ULT_POS.set(c.usuario,{lat:p.lat,lon:p.lon,t:Date.now()});
      await db.from("posiciones").insert({conductor:c.usuario,lat:p.lat,lon:p.lon,vel:p.vel||0});}
  }
}
if(GPS_PLAT){
  refrescarGPS();
  cron.schedule("* * * * *",()=>{refrescarGPS().catch(e=>console.error("refrescarGPS:",e.message))});
  console.log("GPS activo: "+GPS_PLAT+" — refresco cada minuto");
}else console.log("GPS sin configurar (GPS_PLATFORM vacía)");
// ══ Resumen del viaje en curso: el MISMO cálculo que usa la liquidación ══
async function resumenViaje(u){
  const{data:yo}=await db.from("conductores").select("turno_ini,nombre,en_turno").eq("usuario",u).maybeSingle();
  const inicio=(yo&&yo.turno_ini)||new Date(Date.now()-7*86400000).toISOString();
  const fin=new Date().toISOString();
  const st=await leerStock(u);
  const quedan=Object.keys(st.prods).reduce((s,k)=>s+Number(st.prods[k]||0),0);
  const [vts0,mov,trs,gas0,perd,tds,ent0]=await Promise.all([
    db.from("ventas").select("*").eq("conductor",u).gte("creado",inicio).lte("creado",fin),
    db.from("stock_mov").select("motivo,delta").eq("conductor",u).gte("creado",inicio),
    db.from("traspasos").select("*").or("de.eq."+u+",para.eq."+u).gte("creado",inicio),
    db.from("gastos").select("id,categoria,monto,detalle,rechazado,creado").eq("conductor",u).gte("creado",inicio),
    db.from("perdidas").select("motivo,valor,costo,detalle,tipo").eq("conductor",u).gte("creado",inicio),
    db.from("ventas").select("tienda").eq("conductor",u).gte("creado",inicio),
    db.from("entregas").select("id,monto,estado,nota,creado").eq("conductor",u).gte("creado",inicio)
  ]).then(r=>r.map(x=>x.data||[]));
  /* 175 · fuera: ventas anuladas y gastos rechazados; se descuenta el efectivo ya entregado al dueño */
  const vts=vts0.filter(v=>!v.anulada),gas=gas0.filter(g=>!g.rechazado),ent=ent0.filter(e=>e.estado!=="rechazada");
  const entregas=Math.round(ent.reduce((s,e)=>s+Number(e.monto||0),0)*100)/100;
  const sum=(a,f)=>a.reduce((s,x)=>s+Number(f(x)||0),0);
  const efectivo=sum(vts,v=>v.metodo==="yape"?0:v.efectivo);
  const yape=sum(vts.filter(v=>v.metodo==="yape"),v=>v.total);
  const fiado=sum(vts,v=>v.credito), abonos=sum(vts,v=>v.abono);
  const gastos=sum(gas,g=>g.monto);
  const merm=perd.filter(p=>!/^ajuste/.test(p.tipo||""));   /* 177 */
  const mSum=(m)=>mov.filter(x=>x.motivo===m).reduce((s,x)=>s+Math.abs(Number(x.delta||0)),0);
  const DT=await dineroTr(u,inicio,fin);   /* 185 */
  return{
    conductor:u,nombre:(yo&&yo.nombre)||u,en_turno:!!(yo&&yo.en_turno),inicio,fin,
    dias:Math.max(1,Math.round((new Date(fin)-new Date(inicio))/86400000)),
    ventas:{n:vts.length,total:sum(vts,v=>v.total),efectivo,yape,fiado,abonos},
    efectivo_esperado:Math.round((efectivo+abonos-gastos-entregas+DT.neto)*100)/100,
    traspasos_dinero:DT,   /* 185 · cobros y pagos de cuentas, compras al contado a independientes */
    entregas:{total:entregas,n:ent.length,detalle:ent},
    gastos:{total:gastos,detalle:gas},
    perdidas:{total:sum(merm,p=>p.valor),costo:sum(merm,p=>p.costo),n:merm.length,detalle:merm,
      ajustes:{n:perd.length-merm.length}},
    mercaderia:{cargado:mSum("carga"),recibido_en_ruta:mSum("traspaso_recibe"),
      vendido:mSum("venta"),devuelto:mSum("traspaso_envia"),queda:quedan},
    tiendas_atendidas:new Set(tds.map(v=>v.tienda).filter(n=>!/^↔/.test(String(n||"")))).size,
    traspasos:trs.map(t=>({id:t.id,de:t.de,para:t.para,estado:t.estado})),
    puede_liquidar:quedan===0
  };
}
/* ═══ 183 · CIERRE DE VIAJE DEL INDEPENDIENTE ═══
   No liquida con el dueño. Cuenta lo que le sobró (lo que falta es pérdida; lo no útil,
   merma; lo que sobra de más se ajusta y se avisa), ve su ganancia y el sobrante útil sigue
   siendo suyo, a su costo (entra en su siguiente carga). */
async function resumenIndep(u){
  const{data:yo}=await db.from("conductores").select("turno_ini,nombre,en_turno").eq("usuario",u).maybeSingle();
  const{data:ult}=await db.from("cierres_indep").select("fin").eq("conductor",u).order("id",{ascending:false}).limit(1).maybeSingle();
  const inicio=(yo&&yo.turno_ini)||(ult&&ult.fin)||new Date(Date.now()-30*86400000).toISOString();
  const fin=new Date().toISOString();
  const[vts0,gas0,perd0,cm]=await Promise.all([
    db.from("ventas").select("*").eq("conductor",u).gte("creado",inicio),
    db.from("gastos").select("id,categoria,monto,detalle,rechazado,creado").eq("conductor",u).gte("creado",inicio),
    db.from("perdidas").select("motivo,valor,costo,detalle,tipo,creado").eq("conductor",u).gte("creado",inicio),
    db.from("creditos_mov").select("tipo,monto,tienda_id,acreedor,por").eq("acreedor",u).gte("creado",inicio)
  ]).then(r=>r.map(x=>x.data||[]));
  const vts=vts0.filter(v=>!v.anulada),gas=gas0.filter(g=>!g.rechazado),per=perd0.filter(p=>!/^ajuste/.test(p.tipo||""));
  const sum=(a,f)=>Math.round(a.reduce((x,y)=>x+Number(f(y)||0),0)*100)/100;
  const vendido=sum(vts,v=>v.total),costoV=sum(vts,v=>v.costo);
  const efectivo=sum(vts,v=>v.metodo==="yape"?0:v.efectivo),yape=sum(vts.filter(v=>v.metodo==="yape"),v=>v.total);
  const fiado=sum(cm.filter(m=>m.tipo==="cargo"),m=>m.monto),cobrado=sum(cm.filter(m=>m.tipo!=="cargo"),m=>m.monto);
  const perdidas=sum(per,p=>p.costo),gastos=sum(gas,g=>g.monto);
  const vs=await valorStock(u);
  const DT=await dineroTr(u,inicio,fin);   /* 185 */
  return {conductor:u,nombre:(yo&&yo.nombre)||u,en_viaje:!!(yo&&yo.en_turno),inicio,fin,traspasos_dinero:DT,
    ventas:{n:vts.length,total:vendido,efectivo,yape,costo:costoV},
    fiado,cobrado,perdidas:{costo:perdidas,n:per.length,detalle:per},gastos:{total:gastos,detalle:gas},
    ganancia:Math.round((vendido-costoV-perdidas-gastos)*100)/100,
    efectivo_esperado:Math.round((efectivo+cobrado-gastos+DT.neto)*100)/100,
    sobrante:{valor:vs.valor,det:vs.det,unidades:Object.values(vs.prods).reduce((a,b)=>a+Number(b||0),0)}};
}
app.get("/conductor/cierre/resumen",authC,async(req,res)=>{
  res.set("Cache-Control","no-store");
  if(!(await independientes()).has(req.cond.u))return res.status(403).json({ok:false,error:"Solo para independientes"});
  try{res.json({ok:true,resumen:await resumenIndep(req.cond.u)});}catch(e){res.status(500).json({ok:false,error:e.message});}
});
app.post("/conductor/cierre",authC,async(req,res)=>{
  const u=req.cond.u;
  if(!(await independientes()).has(u))return res.status(403).json({ok:false,error:"Solo para independientes (los empleados liquidan)"});
  const{data:trA}=await db.from("traspasos").select("id").or(`de.eq.${u},para.eq.${u}`).in("estado",TR_ACT);
  if((trA||[]).length)return res.status(409).json({ok:false,motivo:"traspaso_activo",error:"Tienes un traspaso sin terminar: termínalo o cancélalo antes de cerrar tu viaje."});
  const st=await leerStock(u),ids=Object.keys(st.prods);
  const conteo=(req.body.conteo&&typeof req.body.conteo==="object")?req.body.conteo:{};
  const{data:cat}=await db.from("catalogo").select("id,nombre,precio,precios").in("id",ids.length?ids:["-"]);
  const nom={},pv={};(cat||[]).forEach(p=>{nom[p.id]=p.nombre;pv[p.id]=Number(p.precio||0)||Number((p.precios&&Object.values(p.precios)[0])||0);});
  const hechos=[],falt={},noUtil={},sobra={};
  ids.forEach(id=>{
    const sis=Number(st.prods[id]||0),c=conteo[id];
    if(!c)return;
    const cont=num(c.cant,0,99999,sis),nu=Math.min(cont,num(c.no_util,0,99999,0));
    if(cont<sis)falt[id]=Math.round((sis-cont)*1000)/1000;
    if(cont>sis)sobra[id]=Math.round((cont-sis)*1000)/1000;
    if(nu>0)noUtil[id]={cant:nu,motivo:limpia(c.motivo,40)||"no útil al cerrar"};
  });
  const perdida=async(prods,motivo,tipo)=>{
    const mv=await moverStock(u,Object.fromEntries(Object.keys(prods).map(id=>[id,-prods[id]])),tipo,"cierre");
    const valor=Math.round(Object.keys(prods).reduce((a,id)=>a+prods[id]*(pv[id]||0),0)*100)/100;
    const det=Object.keys(prods).map(id=>(nom[id]||id)+" ×"+prods[id]).join(", ");
    await db.from("perdidas").insert({conductor:u,motivo,tipo:"merma",valor,costo:mv.costo,detalle:det,prods});
    hechos.push(motivo+": "+det+" (S/"+mv.costo.toFixed(2)+" al costo)");
  };
  if(Object.keys(falt).length)await perdida(falt,"faltante al contar","faltante");
  const porMot={};Object.keys(noUtil).forEach(id=>{const m=noUtil[id].motivo;(porMot[m]=porMot[m]||{})[id]=noUtil[id].cant;});
  for(const m of Object.keys(porMot))await perdida(porMot[m],m,"merma");
  if(Object.keys(sobra).length){
    await moverStock(u,sobra,"ajuste","cierre");
    const det=Object.keys(sobra).map(id=>(nom[id]||id)+" +"+sobra[id]).join(", ");
    hechos.push("tenía de más: "+det);
    await evento("cierre_sobra","⚖️ "+u+" contó más de lo que dice el sistema",det+". Se ajustó su stock al contar al cerrar su viaje: puede haber una venta o un traspaso sin registrar.","");
  }
  const resumen=await resumenIndep(u);
  const cont=(req.body.efectivo_contado===undefined||req.body.efectivo_contado===null||req.body.efectivo_contado==="")?null:num(req.body.efectivo_contado,0,999999);
  const dif=cont==null?null:Math.round((cont-resumen.efectivo_esperado)*100)/100;
  const{data:ci,error}=await db.from("cierres_indep").insert({conductor:u,inicio:resumen.inicio,fin:resumen.fin,resumen,conteo:{faltante:falt,no_util:noUtil,sobra,hechos},efectivo_contado:cont,diferencia:dif,nota:limpia(req.body.nota,300)||null}).select().single();
  if(error)return res.status(500).json({ok:false,error:"No se pudo guardar el cierre: "+error.message});
  await db.from("conductores").update({en_turno:false,turno_hora:resumen.fin,turno_ini:null}).eq("usuario",u);
  await db.from("logs").insert({tipo:"turno",detalle:u+" termina (cierre de independiente #"+ci.id+")"});
  await db.from("kardex").insert({conductor:u,tipo:"cierre_indep",detalle:"Vendido S/"+resumen.ventas.total.toFixed(2)+" · ganancia S/"+resumen.ganancia.toFixed(2)+" · sobrante "+resumen.sobrante.unidades+" unid (S/"+resumen.sobrante.valor.toFixed(2)+" al costo)"});
  await evento("cierre_indep","🏁 Cierre de viaje — "+resumen.nombre+" (independiente)","Vendió S/"+resumen.ventas.total.toFixed(2)+" · costo S/"+resumen.ventas.costo.toFixed(2)+" · pérdidas S/"+resumen.perdidas.costo.toFixed(2)+" · gastos S/"+resumen.gastos.total.toFixed(2)+" · ganancia S/"+resumen.ganancia.toFixed(2)+" · le sobraron "+resumen.sobrante.unidades+" unid (S/"+resumen.sobrante.valor.toFixed(2)+" al costo).",String(ci.id));
  res.json({ok:true,id:ci.id,resumen,diferencia:dif,hechos});
});
app.get("/conductor/cierres",authC,async(req,res)=>{
  const{data}=await db.from("cierres_indep").select("id,inicio,fin,resumen,efectivo_contado,diferencia").eq("conductor",req.cond.u).order("id",{ascending:false}).limit(30);
  res.set("Cache-Control","no-store").json({ok:true,cierres:(data||[]).map(c=>({id:c.id,inicio:c.inicio,fin:c.fin,vendido:c.resumen&&c.resumen.ventas&&c.resumen.ventas.total,ganancia:c.resumen&&c.resumen.ganancia,sobrante:c.resumen&&c.resumen.sobrante&&c.resumen.sobrante.valor,diferencia:c.diferencia}))});
});
app.get("/conductor/resumen",authC,async(req,res)=>{
  res.set("Cache-Control","no-store");
  try{res.json({ok:true,resumen:await resumenViaje(req.cond.u)});}
  catch(e){res.status(500).json({ok:false,error:e.message});}
});
app.get("/admin/comprobantes",authA,async(req,res)=>{
  res.set("Cache-Control","no-store");
  const d=String(req.query.desde||"").slice(0,10),h=String(req.query.hasta||"").slice(0,10);
  const q=String(req.query.q||"").trim().slice(0,40);
  let s=db.from("ventas").select("id,boleta,tienda,conductor,total,metodo,efectivo,credito,abono,anulada,nota_boleta,creado,items,editada_en").order("id",{ascending:false}).limit(300);
  if(/^\d{4}-\d{2}-\d{2}$/.test(d))s=s.gte("creado",iniDia(d));
  if(/^\d{4}-\d{2}-\d{2}$/.test(h))s=s.lte("creado",finDia(h));
  const{data}=await s;
  let rows=data||[];
  const cond=limpia(req.query.conductor,20),est=limpia(req.query.estado,12),met=limpia(req.query.metodo,12);
  if(cond&&cond!=="todos")rows=rows.filter(v=>v.conductor===cond);
  {const IND=await independientes();if(!(cond&&IND.has(cond)))rows=rows.filter(v=>!IND.has(v.conductor));}   /* 183 · sus notas de venta no son tus boletas */
  if(est==="anuladas")rows=rows.filter(v=>v.anulada);
  else if(est==="vigentes")rows=rows.filter(v=>!v.anulada);
  if(met&&met!=="todos")rows=rows.filter(v=>String(v.metodo||"")===met);
  if(q)rows=rows.filter(v=>[v.boleta,v.tienda,v.conductor].join(" ").toLowerCase().includes(q.toLowerCase()));
  res.json({ok:true,comprobantes:rows,
    total:rows.filter(v=>!v.anulada).reduce((a,v)=>a+Number(v.total||0),0),
    anuladas:rows.filter(v=>v.anulada).length});
});
app.post("/admin/comprobantes/:id",authA,async(req,res)=>{
  const upd={editada_en:new Date().toISOString()};
  if(req.body.tienda!==undefined)upd.tienda=limpia(req.body.tienda,80);
  if(req.body.nota!==undefined)upd.nota_boleta=limpia(req.body.nota,300);
  const{error}=await db.from("ventas").update(upd).eq("id",req.params.id);
  if(error)return res.status(500).json({ok:false,error:error.message});
  await db.from("logs").insert({tipo:"admin",detalle:"Editó el comprobante de la venta #"+req.params.id});
  res.json({ok:true});
});
app.post("/admin/comprobantes/:id/anular",authA,async(req,res)=>{
  const motivo=limpia(req.body.motivo,200);
  if(!motivo||motivo.length<5)return res.status(400).json({ok:false,error:"Escribe el motivo de la anulación"});
  const{data:v}=await db.from("ventas").select("*").eq("id",req.params.id).maybeSingle();
  if(!v)return res.status(404).json({ok:false,error:"Venta no encontrada"});
  if(v.anulada)return res.status(409).json({ok:false,error:"Ya estaba anulada"});
  if(v.traspaso_id)return res.status(409).json({ok:false,error:"Es la venta de un traspaso: anúlalo desde Traspasos (así vuelve también la mercadería)"});   /* 185 */
  await db.from("ventas").update({anulada:true,nota_boleta:"ANULADA: "+motivo,editada_en:new Date().toISOString()}).eq("id",v.id);
  if(Number(v.credito||0)>0&&v.tienda_id){
    const{data:cv}=await db.from("conductores").select("tipo").eq("usuario",v.conductor).maybeSingle();   /* 182 */
    await moverDeuda(v.tienda_id,"abono",Number(v.credito),"Anulación de "+(v.boleta||v.nota_venta||("venta #"+v.id)),"admin",tipoDe(cv)==="independiente"?v.conductor:"dueno");
  }
  try{
    const dev={};
    (Array.isArray(v.items)?v.items:[]).forEach(it=>{if(it&&it.id)dev[it.id]=num(it.c,0,9999);});
    if(Object.keys(dev).length)await moverStock(v.conductor,dev,"anulacion",v.id);
  }catch(e){}
  await db.from("logs").insert({tipo:"admin",detalle:"Anuló "+(v.boleta||("venta #"+v.id))+": "+motivo});
  res.json({ok:true});
});
app.post("/admin/eventos/:id/accion",authA,async(req,res)=>{
  const accion=limpia(req.body.accion,20);
  const{data:ev}=await db.from("eventos").select("*").eq("id",req.params.id).maybeSingle();
  if(!ev)return res.status(404).json({ok:false,error:"Aviso no encontrado"});
  const ref=ev.ref||"";
  let hecho="";
  try{
    if(ev.tipo==="tienda_nueva"){
      if(accion==="aceptar"){
        await db.from("tiendas").update({verificada:true,nueva:false}).eq("id",ref);
        hecho="Tienda verificada: ya no aparece como nueva y entra en la ruta normal.";
      }else if(accion==="rechazar"){
        const{error:eR}=await db.from("tiendas").update({act:false}).eq("id",ref);   /* 175 · antes "activa": columna inexistente, no desactivaba */
        if(eR)throw new Error(eR.message);
        hecho="Tienda desactivada: deja de aparecerle al conductor.";
      }
    }else if(ev.tipo==="tienda_pend"){   /* 181 */
      const par=String(ref).split("|"),tid=Number(par[0])||0;
      const{data:tp}=await db.from("tiendas").select("*").eq("id",tid).maybeSingle();
      if(!tp)throw new Error("La tienda ya no existe");
      if(accion==="misma"){
        const destino=num(req.body.destino,0,1e12,0)||Number(par[1])||0;
        if(!destino)throw new Error("Elige con qué tienda es la misma");
        const r=await fusionarTienda(tid,destino,"el dueño desde la Bandeja");
        if(tp.conductor_reg&&tp.conductor_reg!=="admin")await avisoA(tp.conductor_reg,"🏪 «"+tp.nombre+"» ya estaba registrada como «"+r.destino.nombre+"». Tus ventas pasaron a esa tienda y ya la ves en tu lista.");
        hecho="Unida con «"+r.destino.nombre+"»: pasaron "+r.mov.ventas+" ventas, "+r.mov.visitas+" visitas y "+r.mov.creditos_mov+" movimientos de crédito.";
      }else if(accion==="aceptar"||accion==="nueva"){
        await db.from("tiendas").update({estado_reg:"ok",posible_dup:null,verificada:true,nueva:false}).eq("id",tid);
        asegurarCodigos().catch(()=>{});   /* 184 */
        if(tp.conductor_reg&&tp.conductor_reg!=="admin")await avisoA(tp.conductor_reg,"✓ La tienda «"+tp.nombre+"» fue aprobada.");
        hecho="Aprobada como tienda nueva. La ven los conductores de ese lugar"+(esProtegida(await getParams(),tp.ubigeo)?" (zona protegida: los independientes solo si se la habilitas)":"")+".";
      }else if(accion==="rechazar"){
        await db.from("tiendas").update({estado_reg:"rechazada",act:false}).eq("id",tid);
        const{data:vv}=await db.from("ventas").select("id").eq("tienda_id",tid);
        if(tp.conductor_reg&&tp.conductor_reg!=="admin")await avisoA(tp.conductor_reg,"✗ La tienda «"+tp.nombre+"» no fue aprobada y deja de aparecer en tu lista.");
        hecho="Rechazada: deja de aparecerle al conductor."+((vv||[]).length?(" Sus "+vv.length+" ventas quedan registradas."):"");
      }
    }else if(ev.tipo==="boleta"){
      if(accion==="aceptar"){
        await db.from("boletas").update({estado:"enviada"}).eq("id",ref);
        hecho="Comprobante marcado como enviado.";
      }
    }else if(ev.tipo==="liquidacion"){
      if(accion==="aceptar"){
        await db.from("liquidaciones").update({estado:"confirmada",confirmada_en:new Date().toISOString()}).eq("id",ref);
        hecho="Liquidación confirmada.";
      }else if(accion==="rechazar"){
        await db.from("liquidaciones").update({estado:"observada",nota:limpia(req.body.nota,200)||"Observada desde la bandeja",confirmada_en:new Date().toISOString()}).eq("id",ref);
        hecho="Liquidación marcada como observada.";
      }
    }else if(ev.tipo==="gastos"){
      if(accion==="rechazar"){
        await db.from("gastos").update({rechazado:true,nota:limpia(req.body.nota,200)||"Rechazado por el dueño"}).eq("id",ref);
        hecho="Gasto rechazado: no cuenta en la liquidación.";
      }else hecho="Gasto aprobado.";
    }else if(ev.tipo==="credito_sin_permiso"){
      if(accion==="aceptar"){
        await db.from("tiendas").update({cr:true}).eq("id",ref);
        hecho="Crédito autorizado para esa tienda.";
      }else if(accion==="rechazar"){
        hecho="Marcado para revisar: anula la venta desde Comprobantes si corresponde.";
      }
    }else if(ev.tipo==="entrega"){
      if(accion==="aceptar"){
        await db.from("entregas").update({estado:"confirmada",confirmada_en:new Date().toISOString()}).eq("id",ref);
        hecho="Entrega confirmada: se descuenta de lo que debe rendir en la liquidación.";
      }else if(accion==="rechazar"){
        await db.from("entregas").update({estado:"rechazada",confirmada_en:new Date().toISOString()}).eq("id",ref);
        hecho="Entrega rechazada: NO se descuenta de su liquidación.";
      }
    }else if(ev.tipo==="ajuste"){
      const{data:pf}=await db.from("perdidas").select("*").eq("id",ref).maybeSingle();
      if(pf&&pf.tipo==="ajuste_pendiente"&&accion==="aceptar"){
        const pr=pf.prods||{};
        await moverStock(pf.conductor,Object.fromEntries(Object.keys(pr).map(id=>[id,-Number(pr[id]||0)])),"ajuste",null);
        await db.from("perdidas").update({tipo:"ajuste"}).eq("id",pf.id);
        hecho="Ajuste aceptado: se descontó de su stock.";
      }else if(pf&&pf.tipo==="ajuste_pendiente"&&accion==="rechazar"){
        await db.from("perdidas").update({tipo:"ajuste_rechazado"}).eq("id",pf.id);
        hecho="Ajuste rechazado: su stock queda como estaba.";
      }
    }else if(ev.tipo==="carga"){
      hecho=(accion==="aceptar")?"Diferencias aceptadas.":"Marcado para revisar con el conductor.";
    }else if(ev.tipo==="dias_sugeridos"){
      const par=String(ref).split("|"), tid=Number(par[0])||0, dn=diasNorm(par[1]);
      if(accion==="aceptar"&&tid){
        await db.from("tiendas").update({dias_atiende:dn,dias_no:diasNoTexto(dn)}).eq("id",tid);
        await db.from("logs").insert({tipo:"tienda",detalle:"#"+tid+" días → "+diasTexto(dn)+" (propuesto por el conductor)"});
        hecho="Días actualizados: "+diasTexto(dn)+". Cambia cuándo entra a la ruta y cómo se cuenta su reposición.";
      }else if(accion==="rechazar"){
        hecho="Propuesta descartada: la tienda mantiene sus días.";
      }
    }else if(ev.tipo==="ritmo_sugerido"){
      const par=String(ref).split("|"), tid=Number(par[0])||0, rid=par[1]||"";
      if(accion==="aceptar"&&tid&&rid){
        const R2=ritmoDe(await getParams(),rid);
        await db.from("tiendas").update({ritmo:R2.id}).eq("id",tid);
        await db.from("logs").insert({tipo:"tienda",detalle:"#"+tid+" ritmo → "+R2.nombre+" (propuesto por el conductor)"});
        hecho="Ciclo cambiado a "+R2.nombre+": desde ahora se mide con "+R2.ciclo_dias+" días.";
      }else if(accion==="rechazar"){
        hecho="Propuesta descartada: la tienda sigue con su ciclo actual.";
      }
    }
  }catch(e){return res.status(500).json({ok:false,error:e.message});}
  await db.from("eventos").update({visto:true,resuelto:accion,resuelto_en:new Date().toISOString()}).eq("id",ev.id);
  await db.from("logs").insert({tipo:"admin",detalle:"Aviso #"+ev.id+" ("+ev.tipo+") → "+accion});
  res.json({ok:true,hecho:hecho||"Aviso archivado."});
});
app.post("/admin/eventos/vistos",authA,async(req,res)=>{
  const ids=(Array.isArray(req.body.ids)?req.body.ids:[]).slice(0,200);
  if(!ids.length)return res.json({ok:true});
  await db.from("eventos").update({visto:true}).in("id",ids);
  res.json({ok:true});
});
app.get("/admin/primera-venta",authA,async(req,res)=>{
  const cond=limpia(req.query.conductor,20),tienda=limpia(req.query.tienda,80);
  let q=db.from("ventas").select("creado").order("creado",{ascending:true}).limit(1);
  if(cond&&cond!=="todos")q=q.eq("conductor",cond);
  if(tienda)q=q.eq("tienda",tienda);
  const{data}=await q;
  res.json({ok:true,fecha:(data&&data[0])?data[0].creado:null});
});
app.get("/admin/params",authA,async(req,res)=>{
  res.set("Cache-Control","no-store");
  const _p=await getParams();
  res.json({ok:true,params:_p,ritmos:ritmosDe(_p),cortes:CORTES_CICLO,niveles:NIVEL_TXT});
});
app.post("/admin/params",authA,async(req,res)=>{
  const b=req.body||{},kv=await getParams();
  const txt=(v,n)=>limpia(v,n||60);
  /* 175 · "Parámetros del sistema" (formato plano): antes el servidor los ignoraba y aun
     así respondía ok. Se guardan y se espejan con su equivalente de Configuración. */
  const PLANOS={limite_credito:[0,100000],umbral_repo:[1,100000],repo_resta_parcial:[0,60],margen_liq:[0,1000],
    vida_util:[1,60],deuda_dias:[1,365],yape_umbral:[0,100000],dup_radio_m:[1,500],tope_gastos:[0,100000],inactiva_dias:[1,365]};
  Object.keys(PLANOS).forEach(k=>{if(b[k]!==undefined&&b[k]!==null&&b[k]!=="")kv[k]=num(b[k],PLANOS[k][0],PLANOS[k][1]);});
  ["precio_tipo","precio_conductor"].forEach(k=>{if(b[k]&&typeof b[k]==="object"){kv[k]={};
    Object.keys(b[k]).slice(0,40).forEach(x=>{const kk=limpia(x,25);if(kk)kv[k][kk]=num(b[k][x],-90,300,0);});}});
  if(Array.isArray(b.gasto_cats))kv.gasto_cats=b.gasto_cats.slice(0,20).map(x=>limpia(x,20)).filter(Boolean);
  if(Array.isArray(b.zonas)){
    kv.zonas=b.zonas.slice(0,40).map(z=>({id:num(z&&z.id,0,1e15,Date.now()),nombre:txt(z&&z.nombre,40),ajuste:num(z&&z.ajuste,-90,300,0),
      conductor:(z&&z.conductor)?limpia(z.conductor,20):null,color:/^#[0-9a-f]{6}$/i.test(String(z&&z.color))?z.color:"#B97A1F",
      poligono:(Array.isArray(z&&z.poligono)?z.poligono:[]).slice(0,300).map(q=>[num(q&&q[0],-90,90),num(q&&q[1],-180,180)]).filter(q=>q[0]&&q[1])}))
      .filter(z=>z.nombre&&z.poligono.length>=3);
    ZONAS_CACHE={t:0,z:[]};
  }
  // ── 0. Ritmos de reposición de las tiendas ──
  if(Array.isArray(b.ritmos)){
    const vistos={};
    const lista=b.ritmos.map(r=>({id:limpia(r.id,20),nombre:limpia(r.nombre,30),emoji:limpia(r.emoji,4),
      ciclo_dias:num(r.ciclo_dias,1,120,3),umbral_repo:num(r.umbral_repo,1,100000,40),
      resta_parcial:num(r.resta_parcial,0,60,2),dias_perdido:num(r.dias_perdido,7,365,30),
      pesos:(Array.isArray(r.pesos)&&r.pesos.length===6)?r.pesos.map(x=>num(x,0,999,0)):[5,12,22,45,65,80],
      desc:limpia(r.desc,160)}))
      .filter(r=>{ if(!r.id||vistos[r.id])return false; vistos[r.id]=1; return true; });
    if(lista.length)kv.ritmos=lista;
  }
  // ── 0.b Días de atención ──
  if(b.dias_cfg)kv.dias_cfg={
    peso_cerrada:num(b.dias_cfg.peso_cerrada,0,1,0.15),
    avisar_pedido:b.dias_cfg.avisar_pedido!==false,
    avisar_ruta:b.dias_cfg.avisar_ruta!==false};
  // ── 1. Negocio ──
  if(b.negocio)kv.negocio={nombre:txt(b.negocio.nombre,60),
    tel:String(b.negocio.tel||"").replace(/\D/g,"").slice(0,15),moneda:txt(b.negocio.moneda,6)||"S/"};
  // ── 2. Crédito y cobranza ──
  if(b.credito_cfg)kv.credito_cfg={limite:num(b.credito_cfg.limite,0,100000,230),
    dias_vencida:num(b.credito_cfg.dias_vencida,1,180,30),
    fiar_sin_permiso:b.credito_cfg.fiar_sin_permiso!==false,
    aviso_desde:num(b.credito_cfg.aviso_desde,0,100000,150)};
  // ── 3. Operación diaria ──
  if(b.operacion)kv.operacion={hora_informe:num(b.operacion.hora_informe,0,23,22),
    tope_gasto:num(b.operacion.tope_gasto,0,100000,350),
    metros_entrega:num(b.operacion.metros_entrega,20,5000,300),
    min_detenido:num(b.operacion.min_detenido,5,240,45),
    radio_dup_m:num(b.operacion.radio_dup_m,1,200,15),
    min_gps_respaldo:num(b.operacion.min_gps_respaldo,1,120,10)};
  // ── 4. Mermas e inventario ──
  if(b.mermas_cfg)kv.mermas_cfg={aviso_desde:num(b.mermas_cfg.aviso_desde,0,100000,30),
    ajuste_requiere_ok:!!b.mermas_cfg.ajuste_requiere_ok,
    liquidar_con_stock:!!b.mermas_cfg.liquidar_con_stock};
  // ── 5. Catálogo ──
  if(b.catalogo_cfg)kv.catalogo_cfg={precio_cat_nueva:num(b.catalogo_cfg.precio_cat_nueva,0,10000,0),
    vender_sin_precio:b.catalogo_cfg.vender_sin_precio!==false,
    conductor_cambia_precio:b.catalogo_cfg.conductor_cambia_precio!==false};
  if(Array.isArray(b.tipos_tienda))kv.tipos_tienda=b.tipos_tienda.slice(0,12).map(t=>limpia(t,20)).filter(Boolean);
  if(b.precios_cat&&typeof b.precios_cat==="object"){
    kv.precios_cat={};
    Object.keys(b.precios_cat).slice(0,12).forEach(t=>{
      const tt=limpia(t,20);if(!tt)return;kv.precios_cat[tt]={};
      Object.keys(b.precios_cat[t]||{}).slice(0,60).forEach(k=>{
        const kk=limpia(k,20),v=num(b.precios_cat[t][k],0,10000);if(kk&&v)kv.precios_cat[tt][kk]=v;});
    });
  }
  if(b.costos&&typeof b.costos==="object"){
    kv.costos={};Object.keys(b.costos).slice(0,60).forEach(k=>{const kk=limpia(k,20);if(kk)kv.costos[kk]=num(b.costos[k],0,10000);});
  }
  // ── 6. Modalidades y almacenes ──
  if(Array.isArray(b.modalidades))kv.modalidades=b.modalidades.slice(0,12).map(m=>({
    id:limpia(m.id,20)||limpia(String(m.nombre||"").toLowerCase().replace(/[^a-z0-9]/g,""),20),
    nombre:txt(m.nombre,40),dias_viaje:num(m.dias_viaje,1,60,3),
    liquida_en:txt(m.liquida_en,20)||"principal",gps:txt(m.gps,12)||"camion",
    almacen:txt(m.almacen,20)||"principal"})).filter(m=>m.id&&m.nombre);
  if(Array.isArray(b.almacenes))kv.almacenes=b.almacenes.slice(0,10).map(a=>({
    id:limpia(a.id,20)||limpia(String(a.nombre||"").toLowerCase().replace(/[^a-z0-9]/g,""),20),
    nombre:txt(a.nombre,50),ref:txt(a.ref,120),
    lat:(a.lat!=null&&a.lat!=="")?num(a.lat,-90,90):null,
    lon:(a.lon!=null&&a.lon!=="")?num(a.lon,-180,180):null,
    activo:a.activo!==false})).filter(a=>a.id&&a.nombre);
  // ── 7. Avisos y funciones que esperan datos ──
  if(b.avisos_cfg){kv.avisos_cfg=kv.avisos_cfg||{};
    Object.keys(b.avisos_cfg).slice(0,20).forEach(k=>{kv.avisos_cfg[limpia(k,25)]=!!b.avisos_cfg[k]});}
  if(b.futuras){kv.futuras=kv.futuras||{};
    Object.keys(b.futuras).slice(0,20).forEach(k=>{kv.futuras[limpia(k,25)]=!!b.futuras[k]});}
  if(b.almacen)kv.almacen={nombre:txt(b.almacen.nombre,60),ref:txt(b.almacen.ref,120),
    lat:(b.almacen.lat!=null)?num(b.almacen.lat,-90,90):null,lon:(b.almacen.lon!=null)?num(b.almacen.lon,-180,180):null};
  /* 175 · un mismo dato, un solo valor: lo que se cambió en cualquiera de las dos pantallas */
  const esp=[["limite_credito","credito_cfg","limite"],["deuda_dias","credito_cfg","dias_vencida"],
    ["tope_gastos","operacion","tope_gasto"],["dup_radio_m","operacion","radio_dup_m"]];
  esp.forEach(([plano,grupo,clave])=>{
    const vinoPlano=b[plano]!==undefined&&b[plano]!==null&&b[plano]!=="";
    const vinoGrupo=b[grupo]&&b[grupo][clave]!==undefined;
    kv[grupo]=kv[grupo]||{};
    if(vinoGrupo)kv[plano]=kv[grupo][clave];
    else if(vinoPlano)kv[grupo][clave]=kv[plano];
  });
  const{error}=await db.from("params").upsert({id:1,kv});
  if(error)return res.status(500).json({ok:false,error:error.message});
  await db.from("logs").insert({tipo:"admin",detalle:"Cambió la configuración del sistema"});
  res.json({ok:true,params:kv});
});
app.get("/health",(req,res)=>res.json({ok:true,v:"5.0",ts:new Date().toISOString()}));

// ════════ AUTENTICACIÓN ════════
app.post("/auth/admin",authLimiter,(req,res)=>{
  const k="A|"+kIP(req);
  if(bloqueado(k))return res.status(429).json({ok:false,error:"Demasiados intentos. Espera 15 minutos."});
  const cl=req.body.clave||"";
  const esAdmin=safeEq(cl,process.env.ADMIN_PASS);
  const esLector=!!process.env.VIEWER_PASS&&safeEq(cl,process.env.VIEWER_PASS);
  if(!esAdmin&&!esLector){falla(k);return res.status(401).json({ok:false,error:"Clave incorrecta"});}
  limpiaFallo(k);
  res.json({ok:true,solo_lectura:esLector,token:jwt.sign(esLector?{a:1,ro:1}:{a:1},SECRET,{expiresIn:"1d"})});
});
app.post("/auth/login",authLimiter,async(req,res)=>{
  const u=String(req.body.usuario||"").toLowerCase().trim(),p=String(req.body.pass||"");
  const k="L|"+kIP(req)+"|"+u;
  if(bloqueado(k))return res.status(429).json({ok:false,error:"Demasiados intentos. Espera 15 minutos."});
  if(!USR_RE.test(u)){falla(k);return res.status(401).json({ok:false,error:"Usuario o contraseña incorrectos"});}
  const{data:c}=await db.from("conductores").select("*").eq("usuario",u).maybeSingle();
  if(!c||!c.activo){falla(k);return res.status(401).json({ok:false,error:"Usuario o contraseña incorrectos"});}
  if(!c.pass_hash){falla(k);return res.status(401).json({ok:false,error:"Esta cuenta aún no tiene contraseña: usa \"Primera vez\""});}
  if(!(await bcrypt.compare(p,c.pass_hash))){falla(k);return res.status(401).json({ok:false,error:"Usuario o contraseña incorrectos"});}
  limpiaFallo(k);
  res.json({ok:true,token:jwt.sign({u,tipo:tipoDe(c)},SECRET,{expiresIn:"30d"}),nombre:c.nombre,tipo:tipoDe(c),camion:c.camion});
});
app.post("/auth/primera-vez",authLimiter,async(req,res)=>{
  const u=String(req.body.usuario||"").toLowerCase().trim(),p=String(req.body.pass||"");
  const k="P|"+kIP(req);
  if(bloqueado(k))return res.status(429).json({ok:false,error:"Demasiados intentos. Espera 15 minutos."});
  if(!USR_RE.test(u)){falla(k);return res.status(404).json({ok:false,error:"Usuario no válido — contacta al administrador"});}
  if(p.length<6)return res.status(400).json({ok:false,error:"Mínimo 6 caracteres"});
  const{data:c}=await db.from("conductores").select("*").eq("usuario",u).maybeSingle();
  if(!c||!c.activo){falla(k);return res.status(404).json({ok:false,error:"Usuario no válido — contacta al administrador"});}
  if(c.pass_hash)return res.status(409).json({ok:false,error:"Este usuario ya tiene contraseña. Si la olvidaste, contacta al administrador."});
  await db.from("conductores").update({pass_hash:await bcrypt.hash(p,10)}).eq("usuario",u);
  await evento("usuario","👤 Usuario activado","@"+u+" ("+c.nombre+") creó su contraseña y ya puede entrar.",u);
  res.json({ok:true,token:jwt.sign({u,tipo:tipoDe(c)},SECRET,{expiresIn:"30d"}),nombre:c.nombre,tipo:tipoDe(c),camion:c.camion});
});
app.post("/auth/cambiar",authC,async(req,res)=>{
  const{data:c}=await db.from("conductores").select("*").eq("usuario",req.cond.u).single();
  if(!(await bcrypt.compare(String(req.body.actual||""),c.pass_hash||"")))return res.status(401).json({ok:false,error:"Contraseña actual incorrecta"});
  if(String(req.body.nueva||"").length<6)return res.status(400).json({ok:false,error:"Mínimo 6 caracteres"});
  await db.from("conductores").update({pass_hash:await bcrypt.hash(String(req.body.nueva),10)}).eq("usuario",req.cond.u);
  res.json({ok:true});
});
app.post("/auth/evento",authC,async(req,res)=>{await db.from("logs").insert({tipo:req.body.tipo||"login",detalle:req.cond.u});res.json({ok:true});});

// ════════ DATOS DEL CONDUCTOR (todo en el formato que la app espera) ════════
app.get("/conductor/datos",authC,async(req,res)=>{
  res.set("Cache-Control","no-store");
  const u=req.cond.u;
  const lim3=new Date(Date.now()-3*24*60*60*1000).toISOString();
  const [tds, vHoy, peds, ultV, cols, avs, leidos, movHoy, yo, cg, trs, trsOut, trsOk, cat, cats] = await Promise.all([
    db.from("tiendas").select("*").eq("act",true),
    db.from("visitas").select("*").eq("fecha",hoy()),
    db.from("pedidos").select("*").in("estado",["pendiente"]).order("id",{ascending:true}).limit(500),   /* 184 · vigentes */
    db.from("ventas").select("id,tienda_id,creado,total,resumen,items,conductor,anulada,nota_venta,boleta").order("creado",{ascending:false}).limit(400),
    db.from("conductores").select("usuario,nombre,tipo").eq("activo",true).neq("usuario",u),
    db.from("avisos").select("*").or(`para.eq.${u},para.eq.todos`).order("id",{ascending:false}).limit(20),
    db.from("avisos_leidos").select("aviso_id").eq("usuario",u),
    db.from("creditos_mov").select("tipo,monto,por,creado").eq("por",u).gte("creado",iniDia(hoy())),
    db.from("conductores").select("usuario,tipo,lugares,lat,lon,gps_fuente,gps_hora,en_turno,turno_ini,lat_cel,lon_cel,cel_hora,modalidad").eq("usuario",u).maybeSingle(),
    db.from("cargas").select("*").eq("conductor",u).eq("estado","pendiente").order("id",{ascending:false}).limit(1).maybeSingle(),
    db.from("traspasos").select("*").eq("para",u).in("estado",TR_ACT),
    db.from("traspasos").select("*").eq("de",u).in("estado",TR_ACT),
    db.from("traspasos").select("*").eq("estado","completado").gte("creado",lim3).or(`de.eq.${u},para.eq.${u}`),
    db.from("catalogo").select("id,cat,nombre,precio,precios,costo,activo,no_tipos").or("activo.is.null,activo.eq.true"),
    db.from("categorias").select("*").eq("activa",true).order("orden")
  ]).then(rs=>rs.map(x=>x&&x.data));
  const params=await getParams();await zonasVivas();
  /* 181 · solo las tiendas de sus lugares (y en zona protegida, las habilitadas) */
  const yoC=Object.assign({usuario:u},yo||{});
  /* 182 · deudas por acreedor: todos ven lo que la tienda debe a cualquiera */
  const[{data:cmAll},NOMA]=await Promise.all([db.from("creditos_mov").select("tienda_id,tipo,monto,acreedor"),nombresAcreedores()]);
  const DEU={};(cmAll||[]).forEach(m=>{const d=DEU[m.tienda_id]||(DEU[m.tienda_id]={});const a=acreedorDe(m);d[a]=(d[a]||0)+(m.tipo==="cargo"?1:-1)*Number(m.monto||0);});
  const MIA=tipoDe(yoC)==="independiente"?u:"dueno";
  const deudaDe=tid=>{const d=DEU[tid]||{},det=[];let tot=0;Object.keys(d).forEach(a=>{const m=Math.max(0,Math.round(d[a]*100)/100);if(m>0){det.push({a,n:NOMA[a]||a,m});tot+=m;}});return {tot:Math.round(tot*100)/100,mia:Math.max(0,Math.round((d[MIA]||0)*100)/100),det};};
          const PROX=[],NOMC={};(cols||[]).forEach(c=>{NOMC[c.usuario]=c.nombre||c.usuario;});   /* 184 */
  const pedV=p=>({id:p.id,items:(Array.isArray(p.items)?p.items:[]).map(x=>({p:x.n||x.p||"",c:x.c,id:x.id})),hora:p.hora,nota:p.nota||"",
    fecha:String(p.fecha||hoy()).slice(0,10),fecha_txt:fechaTxt(p.fecha||hoy()),atrasado:String(p.fecha||hoy()).slice(0,10)<hoy(),visita:!!p.visita,txt:txtItems(p.items,p.visita)});
  const tiendas=(tds||[]).filter(t=>puedeVer(yoC,t,params)).map(t=>{
    const vs=(ultV||[]).filter(v=>v.tienda_id===t.id).slice(0,5);
    const RIT=ritmoDe(params,t.ritmo), UMB=RIT.umbral_repo;
    const vsAll=(ultV||[]).filter(v=>v.tienda_id===t.id);
    const DIAS=diasNorm(t.dias_atiende), ABRE=abreHoy(DIAS);
    const dr=diasRepo(vsAll,RIT,t.dr_ajuste,RIT.ciclo_dias,DIAS);
    const ultBaja=(vsAll.length&&Number(vsAll[0].total||0)<UMB)?Number(vsAll[0].total||0):null;
    const vo=(vHoy||[]).find(v=>v.tienda_id===t.id&&v.conductor!==u&&v.tipo==="venta");
    /* 184 · el pedido vigente de la tienda: el mío (de hoy o atrasado), los próximos míos y el de otro conductor */
    const vigT=(peds||[]).filter(p=>(p.tienda_id&&p.tienda_id===t.id)||(!p.tienda_id&&p.tienda&&String(p.tienda).toLowerCase().trim()===String(t.nombre).toLowerCase().trim()));
    const pd=vigT.find(p=>p.conductor===u&&String(p.fecha||hoy()).slice(0,10)<=hoy());
    const pdO=pd?null:vigT.find(p=>p.conductor&&p.conductor!==u&&String(p.fecha||hoy()).slice(0,10)<=hoy());
    vigT.filter(p=>p.conductor===u&&String(p.fecha||"").slice(0,10)>hoy()).forEach(p=>PROX.push(Object.assign(pedV(p),{tienda:t.nombre,tienda_id:t.id})));
    return {n:t.nombre,z:t.zona||"—",tp:t.tipo||"bodega",d:t.dueno||"—",tel:t.tel||"—",
      e:vs.length&&fechaPE(vs[0].creado)===hoy()?"completada":"pendiente",
      cod:t.codigo||undefined,precios:(t.precios&&typeof t.precios==="object"&&!Array.isArray(t.precios))?t.precios:{},cr:!!t.cr,sa:deudaDe(t.id).tot,sa_mio:deudaDe(t.id).mia,sa_det:deudaDe(t.id).det,li:(Number(t.li)||limiteLugar(params,t.ubigeo)),di:"—",ub:t.ubigeo||null,lugar:nombreLugar(t.ubigeo)||undefined,pend:(t.estado_reg==="pendiente")||undefined,
      no:t.notas||"",ab:true,lat:t.lat,lon:t.lon,dr,vip:!!t.vip,act:true,
      ritmo:RIT.id,ciclo:RIT.ciclo_dias,nivel:nivelDe(dr,RIT),
      ritmo_nom:RIT.nombre,ritmo_emo:RIT.emoji,umbral:RIT.umbral_repo,
      dias:DIAS,abre_hoy:ABRE,dias_txt:diasTexto(DIAS),
      nueva:!!t.nueva,verificada:!!t.verificada,foto:t.foto||null,id:t.id,
      h:vs.map(v=>({f:new Date(v.creado).toLocaleDateString("es-PE"),p:v.resumen||"",m:Number(v.total),id:v.id,c:v.conductor,num:v.nota_venta||v.boleta||undefined})),
      ultima_compra:(vs[0]&&Array.isArray(vs[0].items))?vs[0].items.filter(x=>x&&x.id).map(x=>({id:x.id,n:x.n,c:num(x.c,0,9999)})):[],
      compras:(vs||[]).slice(0,2).map(v=>({id:v.id,fecha:v.creado,total:Number(v.total||0),
        items:(Array.isArray(v.items)?v.items:[]).filter(x=>x&&x.id).map(x=>({id:x.id,n:x.n,c:num(x.c,0,9999),pu:num(x.pu,0,10000)}))})),
      pedido:pd?pedV(pd):undefined,
      pedidoHoy:!!pd,
      pedido_otro:pdO?Object.assign(pedV(pdO),{de:NOMA[pdO.conductor]||NOMC[pdO.conductor]||pdO.conductor}):undefined,
      pedido_prox:(()=>{const x=vigT.find(p=>p.conductor===u&&String(p.fecha||"").slice(0,10)>hoy());return x?pedV(x):undefined;})(),
      visitadaPor:vo?{n:vo.conductor,h:vo.hora}:undefined,
      bajoMonto:ultBaja,
      h_ini:t.hora_ini||"",h_fin:t.hora_fin||"",dias_no:t.dias_no||"",
      enRuta:(t.conductor_asig===u)?true:undefined,
      asigA:(t.conductor_asig&&t.conductor_asig!==u)?t.conductor_asig:null,
      miZona:zonaDeCond(t.lat,t.lon,u)};
  });
        const setL=new Set((leidos||[]).map(x=>x.aviso_id));
  const avisos=(avs||[]).map(a=>({id:a.id,txt:a.txt,hora:a.hora,leido:setL.has(a.id)}));
    const fiadoHoy=(movHoy||[]).filter(m=>m.tipo==="cargo").reduce((s,m)=>s+Number(m.monto||0),0);
  const cobradoHoy=(movHoy||[]).filter(m=>m.tipo==="abono").reduce((s,m)=>s+Number(m.monto||0),0);
        console.log(`datos->${u}: categorias=${(cats||[]).length} productos=${(cat||[]).length} tiendas=${tiendas.length}`);
  res.json({ok:true,yo_tipo:tipoDe(yoC),yo_lugares:resumenLugares(yoC),mi_cuenta:MIA,proximos_pedidos:PROX.sort((a,b)=>a.fecha.localeCompare(b.fecha)),params,ritmos:ritmosDe(params),turno_ini:(yo&&yo.turno_ini)||null,en_turno:!!(yo&&yo.en_turno),catalogo:cat||[],categorias:cats||[],tiendas,avisos,colegas:(cols||[]).map(x=>({usuario:x.usuario,nombre:x.nombre,tipo:tipoDe(x)})),
    dia:{fiado:fiadoHoy,cobrado:cobradoHoy},
    gps_camion:(function(){
      const minResp=num(params.operacion&&params.operacion.min_gps_respaldo,1,120,10);
      const frescoCam=(yo&&yo.lat&&yo.gps_hora)&&((Date.now()-new Date(yo.gps_hora).getTime())<minResp*60000);
      if(frescoCam)return{lat:yo.lat,lon:yo.lon,fuente:yo.gps_fuente||"camion",hora:yo.gps_hora};
      if(yo&&yo.lat_cel&&yo.cel_hora)return{lat:yo.lat_cel,lon:yo.lon_cel,fuente:"celular",hora:yo.cel_hora,
        nota:"El GPS del camión no reporta hace más de "+minResp+" min"};
      if(yo&&yo.lat)return{lat:yo.lat,lon:yo.lon,fuente:yo.gps_fuente||"camion",hora:yo.gps_hora,nota:"Última posición conocida"};
      return null;
    })(),
    carga_pendiente:cg?{id:cg.id,items:cg.items,prods:cg.prods||null,detalle:cg.detalle||null}:null,
    traspasos_entrantes:(trs||[]).map(t=>({id:String(t.id),de:t.de_nombre||t.de,items:t.items,estado:t.estado,yo_confirme:!!t.conf_para,otro_confirmo:!!t.conf_de})),
    traspasos_completados:(trsOk||[]).map(t=>({id:String(t.id),items:t.items,rol:t.para===u?"recibe":"entrega",otro:t.para===u?(t.de_nombre||t.de):t.para})),
    traspasos_salientes:(trsOut||[]).map(t=>({id:String(t.id),para:t.para,items:t.items,estado:t.estado,yo_confirme:!!t.conf_de,otro_confirmo:!!t.conf_para}))});
});

// ════════ OPERACIÓN DEL CONDUCTOR ════════
app.post("/ventas",authC,async(req,res)=>{
  const{tienda,items,total,metodo}=req.body;
  /* 175 · cada venta trae un identificador: si llega dos veces (reintento de la cola,
     doble toque), se responde con la primera en vez de registrarla otra vez */
  const uid=limpia(req.body.uid,40)||null;
  if(uid){const{data:ya}=await db.from("ventas").select("id,boleta").eq("uid",uid).maybeSingle();if(ya)return res.json({ok:true,id:ya.id,boleta:ya.boleta,repetida:true});}
  /* 175 · venta rápida (⚡): a un transeúnte, sin tienda, solo al contado. Antes no llegaba al servidor */
  const rapida=req.body.rapida===true;
  let t=null;
  if(!rapida){
    if(req.body.tienda_id){const{data:x}=await db.from("tiendas").select("*").eq("id",req.body.tienda_id).maybeSingle();t=x||null;}
    if(!t){const{data:x}=await db.from("tiendas").select("*").ilike("nombre",String(tienda||"").trim()).maybeSingle();t=x||null;}
    if(!t)return res.status(400).json({ok:false,error:"No identifiqué la tienda: "+tienda});
  }
  if(rapida&&(metodo==="credito"||metodo==="mixto"||num(req.body.credito,0,999999)>0))
    return res.status(400).json({ok:false,error:"La venta rápida es solo al contado (efectivo o Yape)"});
  const _pv=await getParams();
  if(t){   /* 181 */
    const{data:yoV}=await db.from("conductores").select("usuario,tipo,lugares").eq("usuario",req.cond.u).maybeSingle();
    if(yoV&&!puedeVer(yoV,t,_pv))return res.status(403).json({ok:false,error:"La tienda «"+t.nombre+"» no está habilitada para ti. Pídele al dueño que te la habilite."});
  }
  if(_pv.catalogo_cfg&&_pv.catalogo_cfg.vender_sin_precio===false&&(Array.isArray(items)?items:[]).some(x=>!(Number(x&&x.pu)>0)))
    return res.status(400).json({ok:false,error:"Hay productos sin precio en la venta. Ponles precio en el catálogo o activa «Permitir vender productos sin precio»."});
  const resumen=(items||[]).map(x=>`${x.n} x${x.c}`).join(", ");
  const{data:v}=await db.from("ventas").insert({efectivo:num(req.body.efectivo,0,999999),credito:num(req.body.credito,0,999999),abono:num(req.body.abono,0,999999),tienda_id:t?t.id:null,tienda:rapida?"Venta rápida":tienda,conductor:req.cond.u,items:items||[],total:num(total,0,999999),metodo:(["efectivo","yape","credito","mixto"].includes(metodo)?metodo:"efectivo"),resumen,uid}).select().single();
  if(!v){
    if(uid){const{data:ya}=await db.from("ventas").select("id,boleta").eq("uid",uid).maybeSingle();if(ya)return res.json({ok:true,id:ya.id,boleta:ya.boleta,repetida:true});}
    return res.status(500).json({ok:false,error:"No se pudo guardar la venta en la base. Queda en el celular para reintentar."});
  }
  /* 183 · el independiente no usa la serie B001 del dueño: su propia nota de venta */
  const{data:yoNV}=await db.from("conductores").select("tipo").eq("usuario",req.cond.u).maybeSingle();
  const esIndNV=tipoDe(yoNV)==="independiente";
  if(esIndNV&&v){
    try{
      const{data:mias}=await db.from("ventas").select("nota_venta").eq("conductor",req.cond.u);
      let n=0;(mias||[]).forEach(x=>{const m=String(x.nota_venta||"").match(/(\d+)$/);if(m)n=Math.max(n,parseInt(m[1],10));});
      v.nota_venta="NV-"+req.cond.u.toUpperCase().slice(0,10)+"-"+String(n+1).padStart(5,"0");
      await db.from("ventas").update({nota_venta:v.nota_venta}).eq("id",v.id);
    }catch(e){console.error("nota de venta:",e.message);}
  }
  // número de comprobante correlativo, asignado por el servidor
  if(!esIndNV)try{
    /* 177 · la base no acepta dos boletas iguales: si otra venta tomó el número, se pide el siguiente */
    let probado=0;
    for(let intento=0;intento<5&&v&&!v.boleta;intento++){
      const{data:ult}=await db.from("ventas").select("boleta").not("boleta","is",null).order("id",{ascending:false}).limit(1).maybeSingle();
      let n=1;
      if(ult&&ult.boleta){const m=String(ult.boleta).match(/(\d+)$/);if(m)n=parseInt(m[1],10)+1;}
      if(n<=probado)n=probado+1;probado=n;
      const numB="B001-"+String(n).padStart(6,"0");
      const{error:eB}=await db.from("ventas").update({boleta:numB}).eq("id",v.id);
      if(!eB)v.boleta=numB;
    }
  }catch(e){console.error("boleta:",e.message);}
  // ¿venta después de haber liquidado? (cola que llegó tarde, o venta real fuera de viaje)
  let fueraDeTurno=false;
  if(!esIndNV)try{   /* 183 · el independiente no liquida con el dueño */
    const{data:yoT}=await db.from("conductores").select("en_turno,turno_ini").eq("usuario",req.cond.u).maybeSingle();
    fueraDeTurno=!(yoT&&yoT.en_turno);
    if(fueraDeTurno&&v){
      const{data:ult}=await db.from("liquidaciones").select("id,resumen").eq("conductor",req.cond.u).order("id",{ascending:false}).limit(1).maybeSingle();
      await db.from("ventas").update({post_liq:true,liq_id:ult?ult.id:null}).eq("id",v.id);
      await avisarAdmin("⚠️ Venta registrada FUERA DE VIAJE — "+req.cond.u
        +"\nTienda: "+(t&&t.nombre||"—")+" · S/"+Number(total||0).toFixed(2)+" ("+(metodo||"")+")"
        +"\nSe anota como ajuste de la liquidación #"+(ult?ult.id:"—")+", que no se modifica."
        +"\nRevisa si corresponde cobrar aparte.","venta_fuera_viaje",true);
      await db.from("logs").insert({tipo:"venta_post_liq",detalle:req.cond.u+" vendió S/"+Number(total||0).toFixed(2)+" fuera de turno"});
    }
  }catch(e){console.error("post_liq:",e.message);}
  // descontar del stock lo que salió del camión
  try{
    const salida={};
    (Array.isArray(req.body.items)?req.body.items:[]).forEach(it=>{if(it&&it.id)salida[it.id]=-(num(it.c,0,9999));});
    if(Object.keys(salida).length){const mv=await moverStock(req.cond.u,salida,"venta",v&&v.id);
      if(v&&mv)await db.from("ventas").update({costo:mv.costo}).eq("id",v.id);}   /* 183 · costo PEPS de lo vendido */
  }catch(e){console.error("stock venta:",e.message);}
  if(t)await db.from("visitas").insert({tienda_id:t.id,tienda:t.nombre,conductor:req.cond.u,tipo:"venta",fecha:hoy(),hora:horaPE()});
  /* 184 · la venta atiende el pedido vigente de esa tienda; los precios que cambió quedan para ella */
  if(t){try{await atenderPedido(t,req.cond.u,v,items,false);}catch(e){console.error("pedido atendido:",e.message);}
    try{await guardarAcordados(t,req.cond.u,req.body.precios_acordados,_pv);}catch(e){console.error("precio acordado:",e.message);}}
  if(t&&t.dr_ajuste)await db.from("tiendas").update({dr_ajuste:0}).eq("id",t.id);
  const fiado=num(req.body.credito,0,999999)||((metodo==="credito")?num(total,0,999999):0);
  const abono=num(req.body.abono,0,999999);
  /* 182 · cuenta de quién: el empleado fía y cobra para el dueño; el independiente, para sí */
  const{data:yoCr}=await db.from("conductores").select("usuario,tipo,nombre").eq("usuario",req.cond.u).maybeSingle();
  const esInd=tipoDe(yoCr)==="independiente",ACR=esInd?req.cond.u:"dueno";
  const totAntes=(t&&(fiado>0||abono>0))?(await saldosTienda(t.id)).total:0;
  if(abono>0&&t){
    await moverDeuda(t.id,"abono",abono,"Cobro en visita #"+v.id,req.cond.u,ACR);
  }
  if(fiado>0&&t&&esInd){
    await moverDeuda(t.id,"cargo",fiado,"Venta "+(metodo==="mixto"?"mixta":"a crédito")+" #"+v.id,req.cond.u,ACR);
    /* el independiente puede pasar el límite (es su dinero), pero queda avisado y te llega */
    const lim=Number(t.li)||limiteLugar(_pv,t.ubigeo),totDesp=Math.round((totAntes-Math.min(abono,totAntes)+fiado)*100)/100;
    if(lim>0&&totDesp>lim){
      await evento("credito_limite","💳 Fiado sobre el límite — "+t.nombre,
        (yoCr&&yoCr.nombre||req.cond.u)+" (independiente) le fió S/"+fiado.toFixed(2)+". La tienda ya debía S/"+totAntes.toFixed(2)+" y ahora debe S/"+totDesp.toFixed(2)+" en total (límite S/"+lim.toFixed(2)+").",String(t.id));
      avisarAdmin("💳 Fiado sobre el límite: "+req.cond.u+" fió S/"+fiado.toFixed(2)+" a "+t.nombre+" — debe S/"+totDesp.toFixed(2)+" en total (límite S/"+lim.toFixed(2)+")","credito_sin_permiso");
    }
  }
  if(fiado>0&&t&&!esInd&&!t.cr)await evento("credito_sin_permiso","⚠️ Venta al crédito en tienda sin crédito habilitado",
    t.nombre+" · S/"+fiado.toFixed(2)+" · conductor "+req.cond.u,String(t.id));
  if(fiado>0&&t&&!esInd){
    const antes=await saldoHistorial(t.id,"dueno");
    const r=await moverDeuda(t.id,"cargo",fiado,"Venta "+(metodo==="mixto"?"mixta":"a crédito")+" #"+v.id,req.cond.u,"dueno");
    /* 175 · Configuración → Crédito: aviso por cada venta fiada y aviso al pasar un monto */
    const cc=_pv.credito_cfg||{};
    if(cc.fiar_sin_permiso===false){
      await evento("credito_aviso","💳 Venta al crédito — "+t.nombre,req.cond.u+" fió S/"+fiado.toFixed(2)+". Deuda de la tienda ahora: S/"+Number(r.sa||0).toFixed(2)+".",String(t.id));
      avisarAdmin("💳 "+req.cond.u+" fió S/"+fiado.toFixed(2)+" a "+t.nombre+" (deuda S/"+Number(r.sa||0).toFixed(2)+")","credito_sin_permiso");
    }
    const umb=num(cc.aviso_desde,0,100000,0);
    if(umb>0&&antes<umb&&Number(r.sa||0)>=umb){
      await evento("credito_alto","💳 Deuda alta — "+t.nombre,"La deuda llegó a S/"+Number(r.sa).toFixed(2)+" (aviso desde S/"+umb+").",String(t.id));
      avisarAdmin("💳 "+t.nombre+" ya debe S/"+Number(r.sa).toFixed(2),"credito_sin_permiso");
    }
  }
  /* 175 · Configuración → distancia máxima de una entrega: la venta se compara con la
     posición del celular (o del camión) de ese momento */
  try{
    const mE=num(_pv.operacion&&_pv.operacion.metros_entrega,0,100000,0);
    if(mE>0&&t&&t.lat&&t.lon){
      const{data:yo2}=await db.from("conductores").select("lat,lon,gps_hora,lat_cel,lon_cel,cel_hora").eq("usuario",req.cond.u).maybeSingle();
      const fresco=h=>h&&(Date.now()-new Date(h).getTime())<15*60000;
      let pp=null;if(yo2&&fresco(yo2.cel_hora)&&yo2.lat_cel)pp=[Number(yo2.lat_cel),Number(yo2.lon_cel)];else if(yo2&&fresco(yo2.gps_hora)&&yo2.lat)pp=[Number(yo2.lat),Number(yo2.lon)];
      if(pp){const d=Math.hypot((pp[0]-t.lat)*111000,(pp[1]-t.lon)*107000);
        if(d>mE)await evento("entrega_lejos","📍 Venta lejos de la tienda — "+t.nombre,req.cond.u+" registró la venta a unos "+Math.round(d)+" m de la tienda (máximo configurado: "+mE+" m).",String(t.id));}
    }
  }catch(e){}
  try{await db.from("kardex").insert({conductor:req.cond.u,tipo:"venta_detalle",
    detalle:(t?t.nombre:"Venta rápida")+" · S/"+Number(total||0).toFixed(2)+" ("+(metodo||"efectivo")+")"+(fiado>0?" · fiado S/"+fiado.toFixed(2):"")});}catch(e){}
  res.json({ok:true,id:v.id,boleta:v.boleta||v.nota_venta||null,nota_venta:v.nota_venta||undefined});
});
/* 175 · Reportar robo o incidente: llega a la Bandeja del dueño */
app.post("/conductor/incidente",authC,async(req,res)=>{
  const txt=limpia(req.body.texto,400);
  if(!txt||txt.length<5)return res.status(400).json({ok:false,error:"Cuenta qué pasó (al menos unas palabras)"});
  const monto=num(req.body.monto,0,999999,0);
  await evento("incidente","🚨 Robo o incidente — "+req.cond.u,txt+(monto?(" · Monto estimado S/"+monto.toFixed(2)):"")+(req.body.evidencia?" · el conductor dice tener evidencia (foto o denuncia)":"")+". El faltante sigue a su nombre hasta que lo resuelvas en su liquidación.","");
  await db.from("logs").insert({tipo:"incidente",detalle:req.cond.u+": "+txt.slice(0,200)});
  avisarAdmin("🚨 Robo o incidente reportado por "+req.cond.u+": "+txt.slice(0,200),"incidente");
  res.json({ok:true});
});
app.post("/visitas",authC,async(req,res)=>{
  const t=await tiendaPorNombre(req.body.tienda||"");
  /* 175 · el motivo de "No pude visitar" (antes solo se mostraba en el celular) */
  const motivoV=limpia(req.body.motivo,60)||null;
  const esCerrada=!motivoV||/cerrad/i.test(motivoV);
  await db.from("visitas").insert({tienda_id:t?t.id:null,tienda:req.body.tienda,conductor:req.cond.u,tipo:(["venta","fallida","no_quiso","registro"].includes(req.body.tipo)?req.body.tipo:"fallida"),fecha:hoy(),hora:horaPE(),motivo:motivoV});
  if(t&&req.body.tipo==="no_quiso"){try{await atenderPedido(t,req.cond.u,null,[],true);}catch(e){console.error("pedido visita:",e.message);}}   /* 184 */
  if((req.body.tipo||"")==="fallida"){
    const cerradaHoy=t&&!abreHoy(t.dias_atiende);
    await evento("visita","🚫 Visita fallida — "+req.body.tienda,
      req.cond.u+(esCerrada?" la encontró cerrada.":" no pudo atenderla: "+motivoV+".")+" Reprogramada para mañana con prioridad; la reposición sigue contando."
      +(cerradaHoy?" (Según sus días, hoy "+DIA_NOM[diaIdx()]+" no atiende: era esperable.)":""),
      t?t.id:"");
    /* Si el sistema decía que hoy SÍ abre y estaba cerrada, el dato de días
       probablemente esté mal. Se avisa una vez para poder corregirlo. */
    if(t&&!cerradaHoy&&esCerrada){
      const hoyIdx=diaIdx(), prop=diasNorm(t.dias_atiende).split("");
      prop[hoyIdx]="0";
      await evento("dias_sugeridos","📅 ¿Esta tienda cierra los "+DIA_NOM[hoyIdx]+"? — "+t.nombre,
        req.cond.u+" la encontró cerrada un "+DIA_NOM[hoyIdx]+", y según el sistema ese día sí atiende. "
        +"Si es su día de descanso, acepta para quitarlo: "+diasTexto(t.dias_atiende)+" → "+diasTexto(prop.join("")),
        String(t.id)+"|"+prop.join(""));
    }
  }
  if((req.body.tipo||"")==="no_quiso"&&t){
    /* Restar 2 días fijos castigaba igual a una tienda de ciclo 3 que a una de
       ciclo 7. Ahora el descuento es proporcional: ~0,7 ciclos. Para la activa
       siguen siendo 2 días; para la semanal son 5. */
    const _R=ritmoDe(await getParams(),t.ritmo);
    const _d=Math.max(1,Math.round(_R.ciclo_dias*0.7));
    await db.from("tiendas").update({dr_ajuste:num((t.dr_ajuste||0)+_d,0,120)}).eq("id",t.id);
    await evento("visita","🙅 No quiso comprar — "+req.body.tienda,req.cond.u+" ofreció y el dueño decidió no llevar. Se le restan "+_d+" días al contador de reposición ("+_R.nombre+").",t.id);
  }
  if((req.body.tipo||"")==="venta_fuera_zona"){await evento("zona","📍 Venta fuera de zona — "+req.body.tienda,req.cond.u+" registró una venta fuera de las zonas dibujadas ("+(req.body.lat||"?")+", "+(req.body.lon||"?")+").",t?t.id:"");avisarAdmin("📍 Venta fuera de zona: "+req.body.tienda+" por "+req.cond.u,"zona");}
  res.json({ok:true});
});
app.post("/tiendas",authC,async(req,res)=>{
  const b=req.body;
  const _pmsC=await getParams(), _diasC=diasNorm(b.dias);
  /* 181 · el lugar sale del GPS. Queda PENDIENTE (solo la ve quien la registró, hasta que
     el dueño decida) si: está fuera de sus lugares, parece repetida de otra tienda (se
     compara con todas, también las que él no ve), o un independiente la registra en zona
     protegida. Al conductor no se le muestran datos de la otra tienda. */
  const latN=(b.lat==null?null:num(b.lat,-90,90)),lonN=(b.lon==null?null:num(b.lon,-180,180));
  const ub=(latN!=null&&lonN!=null)?ubicarGPS(latN,lonN):null;
  const{data:yoR}=await db.from("conductores").select("usuario,tipo,lugares").eq("usuario",req.cond.u).maybeSingle();
  const cR=Object.assign({usuario:req.cond.u},yoR||{});
  const dup=await buscarRepetida(b.n,latN,lonN,_pmsC);
  const motivos=[];
  if(!habilitadoEn(cR,ub))motivos.push(ub?("está fuera de sus lugares ("+nombreLugar(ub)+")"):"no tiene ubicación GPS");
  if(dup)motivos.push("parece la misma que «"+dup.t.nombre+"» (#"+dup.t.id+(dup.m!=null?(", a "+dup.m+" m"):"")+")");
  if(tipoDe(cR)==="independiente"&&esProtegida(_pmsC,ub))motivos.push("está en zona protegida ("+nombreLugar(ub)+")");
  const pend=motivos.length>0;
  const{data:t,error}=await db.from("tiendas").insert({nombre:b.n,zona:b.z,tipo:b.tp,ritmo:ritmoDe(_pmsC,b.ritmo).id,
    dias_atiende:_diasC,dueno:b.d,tel:String(b.tel||"").replace(/\D/g,"").slice(0,15),notas:b.no||"",hora_ini:limpia(b.h_ini,5),hora_fin:limpia(b.h_fin,5),dias_no:limpia(b.dias_no,30),lat:(b.lat==null?null:num(b.lat,-90,90)),lon:(b.lon==null?null:num(b.lon,-180,180)),foto:fotoOK(b.foto)?b.foto:null,cr:false,sa:0,li:0,vip:false,act:true,nueva:true,verificada:false,conductor_reg:req.cond.u,
    ubigeo:ub,estado_reg:pend?"pendiente":"ok",posible_dup:dup?dup.t.id:null}).select().single();
  if(error)return res.status(500).json({ok:false,error:error.message});
  if(pend){
    await evento("tienda_pend","⏳ Tienda por aprobar — "+b.n,
      "Registrada por "+req.cond.u+" ("+tipoDe(cR)+") en "+(nombreLugar(ub)||"un lugar sin ubicar")+". Queda pendiente porque "+motivos.join("; ")+". Mientras tanto solo la ve quien la registró y le puede vender.",
      String(t.id)+(dup?("|"+dup.t.id):""));
    avisarAdmin("⏳ Tienda por aprobar: "+b.n+" — registrada por "+req.cond.u+". "+motivos.join("; "),"tienda_nueva");
  }else{
    await evento("tienda_nueva","🆕 Tienda nueva por verificar — "+b.n,"Registrada por "+req.cond.u+" en "+(nombreLugar(ub)||b.z||"—")+". Contado habilitado; crédito bloqueado hasta que la verifiques.",t.id);
    avisarAdmin("🆕 Tienda nueva por verificar: "+b.n+" ("+(nombreLugar(ub)||b.z||"—")+") — registrada por "+req.cond.u,"tienda_nueva");
  }
  asegurarCodigos().catch(()=>{});   /* 184 */
  res.json({ok:true,id:t.id,pendiente:pend||undefined,lugar:nombreLugar(ub)||undefined});
});
app.post("/conductor/dias-sugeridos",authC,async(req,res)=>{
  /* Mismo criterio que el ciclo: el conductor propone, el dueño aprueba.
     Es el que está parado en la puerta, así que es quien mejor lo sabe. */
  const id=Number(req.body.tienda_id)||0;
  if(!id)return res.status(400).json({ok:false,error:"Falta la tienda"});
  const{data:t}=await db.from("tiendas").select("id,nombre,dias_atiende").eq("id",id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Tienda no encontrada"});
  const dn=diasNorm(req.body.dias), ant=diasNorm(t.dias_atiende);
  if(dn===ant)return res.json({ok:false,error:"Esos son los días que ya tiene"});
  await evento("dias_sugeridos","📅 Días de atención propuestos — "+t.nombre,
    req.cond.u+" propone cambiar los días: "+diasTexto(ant)+" → "+diasTexto(dn)
    +(diasNoTexto(dn)?(". No atendería: "+diasNoTexto(dn)):". Atendería todos los días.")
    +(limpia(req.body.motivo,200)?" Motivo: "+limpia(req.body.motivo,200):""),
    String(t.id)+"|"+dn);
  res.json({ok:true});
});
app.post("/conductor/ritmo-sugerido",authC,async(req,res)=>{
  /* El conductor es quien ve cómo vende cada tienda. Propone el ciclo; el
     dueño lo acepta o lo rechaza desde la Bandeja. No lo cambia él solo. */
  const id=Number(req.body.tienda_id)||0;
  const _p=await getParams(), R=ritmoDe(_p,req.body.ritmo);
  if(!id||R.id!==String(req.body.ritmo||""))
    return res.status(400).json({ok:false,error:"Falta la tienda o ese ciclo no existe"});
  const{data:t}=await db.from("tiendas").select("id,nombre,ritmo").eq("id",id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Tienda no encontrada"});
  if((t.ritmo||"activa")===R.id)
    return res.json({ok:false,error:"Esa tienda ya está en el ciclo "+R.nombre});
  const ant=ritmoDe(_p,t.ritmo);
  const motivo=limpia(req.body.motivo,200);
  await evento("ritmo_sugerido","🔁 Cambio de ciclo propuesto — "+t.nombre,
    req.cond.u+" propone pasarla de "+ant.nombre+" (ciclo "+ant.ciclo_dias+"d) a "
    +R.nombre+" (ciclo "+R.ciclo_dias+"d)."+(motivo?" Motivo: "+motivo:""),
    String(t.id)+"|"+R.id);
  res.json({ok:true});
});
app.post("/correcciones",authC,async(req,res)=>{
  /* 183 · el independiente corrige su propia venta: se aplica al momento, queda el antes y
     el después, y el dueño recibe el aviso. El empleado propone y el dueño decide (como antes). */
  if((await independientes()).has(req.cond.u)){
    const ref=limpia(req.body.referencia,40),nuevo=num(req.body.monto_correcto,0,999999);
    const{data:mias}=await db.from("ventas").select("*").eq("conductor",req.cond.u);
    const v=(mias||[]).find(x=>!x.anulada&&(x.nota_venta===ref||x.boleta===ref||String(x.id)===ref||String(x.uid)===ref));
    if(!v)return res.status(404).json({ok:false,error:"No encontré esa venta tuya ("+ref+")"});
    const antes=Number(v.total||0),dif=Math.round((nuevo-antes)*100)/100;
    const upd={total:nuevo,editada_en:new Date().toISOString(),nota_boleta:limpia("Corregida por "+req.cond.u+": S/"+antes.toFixed(2)+" → S/"+nuevo.toFixed(2)+" · "+(req.body.motivo||""),300)};
    if(v.metodo==="credito"){upd.credito=Math.max(0,Number(v.credito||0)+dif);
      if(v.tienda_id&&dif)await moverDeuda(v.tienda_id,dif>0?"cargo":"abono",Math.abs(dif),"Corrección de "+(v.nota_venta||("venta #"+v.id)),req.cond.u,req.cond.u);}
    else if(v.metodo!=="yape")upd.efectivo=Math.max(0,Number(v.efectivo||0)+dif);
    await db.from("ventas").update(upd).eq("id",v.id);
    await db.from("correcciones").insert({tienda:req.body.tienda||v.tienda,referencia:ref,monto_correcto:nuevo,motivo:limpia(req.body.motivo,200),conductor:req.cond.u,estado:"aplicada"});
    await db.from("kardex").insert({conductor:req.cond.u,tipo:"correccion",detalle:(v.nota_venta||("#"+v.id))+" "+v.tienda+": S/"+antes.toFixed(2)+" → S/"+nuevo.toFixed(2)+" — "+(req.body.motivo||"")});
    await evento("correccion_indep","✎ Venta corregida por un independiente — "+req.cond.u,(v.nota_venta||("#"+v.id))+" · "+v.tienda+": S/"+antes.toFixed(2)+" → S/"+nuevo.toFixed(2)+". Motivo: "+(req.body.motivo||"—"),String(v.id));
    return res.json({ok:true,aplicada:true,antes,despues:nuevo});
  }
  const{data:c}=await db.from("correcciones").insert({tienda:req.body.tienda,referencia:req.body.referencia,monto_correcto:Number(req.body.monto_correcto)||0,motivo:req.body.motivo,conductor:req.cond.u,estado:"pendiente"}).select().single();
  await evento("correccion","✎ Corrección propuesta — "+req.body.tienda,req.body.referencia+" → S/"+Number(req.body.monto_correcto||0).toFixed(2)+". Motivo: "+req.body.motivo+" (por "+req.cond.u+")",c.id);
  res.json({ok:true,id:c.id});
});
/* ═══ 185 · TRASPASOS: crear (pedir u ofrecer), aceptar, confirmar, rechazar, cancelar ═══ */
const quienEs=u=>(u==="almacen"||USR_RE.test(String(u||"")));
async function vistaTr(t,yo,N){
  const pr=limpiaProds(t.prods);
  const{data:cat}=await db.from("catalogo").select("id,nombre").in("id",Object.keys(pr).length?Object.keys(pr):["-"]);
  const nom={};(cat||[]).forEach(p=>{nom[p.id]=p.nombre;});
  const soyDe=t.de===yo,soyPara=t.para===yo,otro=soyDe?t.para:t.de;
  return {id:t.id,estado:t.estado,modo:t.modo||"pedir",cruce:!!t.cruce,de:t.de,para:t.para,de_n:N[t.de]||t.de_nombre||t.de,para_n:N[t.para]||t.para,
    otro,otro_n:N[otro]||otro,rol:soyDe?"entrega":(soyPara?"recibe":null),iniciador:t.iniciador||t.para,
    items:Object.keys(pr).map(id=>({id,n:nom[id]||id,c:pr[id],pu:t.precios&&t.precios[id]!=null?Number(t.precios[id]):undefined})),
    precio_modo:t.precio_modo||null,total:t.total!=null?Number(t.total):null,pago:t.pago||null,
    conf_de:!!t.conf_de,conf_para:!!t.conf_para,yo_confirme:soyDe?!!t.conf_de:!!t.conf_para,otro_confirmo:soyDe?!!t.conf_para:!!t.conf_de,
    nota:t.nota||"",creado:t.creado,dist_m:t.dist_m||null,anul_motivo:t.anul_motivo||null};
}
app.post("/traspasos",authC,async(req,res)=>{
  const yo=req.cond.u,b=req.body||{},modo=b.modo==="ofrecer"?"ofrecer":"pedir";
  const de=modo==="ofrecer"?yo:String(b.de||""),para=modo==="ofrecer"?String(b.para||""):yo;
  if(!quienEs(de)||!quienEs(para)||de===para)return res.status(400).json({ok:false,error:"Elige con quién es el traspaso"});
  if(de!=="almacen"){const{data:x}=await db.from("conductores").select("usuario").eq("usuario",de).maybeSingle();if(!x)return res.status(400).json({ok:false,error:"Ese conductor no existe"});}
  if(para!=="almacen"){const{data:x}=await db.from("conductores").select("usuario").eq("usuario",para).maybeSingle();if(!x)return res.status(400).json({ok:false,error:"Ese conductor no existe"});}
  const prodsT=limpiaProds(b.prods||b.items);
  if(!Object.keys(prodsT).length)return res.status(400).json({ok:false,error:"Elige al menos un producto"});
  const cruce=(await duenoDe(de))!==(await duenoDe(para));
  const fila={de,de_nombre:b.de_nombre||de,para,prods:prodsT,items:await porCategoria(prodsT),estado:"pendiente",modo,iniciador:yo,cruce,nota:limpia(b.nota,200)||null};
  if(modo==="ofrecer"){
    const f=await faltaStock(yo,prodsT);if(f)return res.status(409).json({ok:false,error:"No tienes suficiente: "+f});
    if(cruce){
      if(!["efectivo","yape","fiado"].includes(b.pago))return res.status(400).json({ok:false,error:"Elige la forma de pago: contado, Yape o fiado"});
      try{const p=await preciosTr(yo,prodsT,b.precio_modo,b.precios);Object.assign(fila,{precio_modo:b.precio_modo,precios:p.precios,total:p.total,pago:b.pago});}
      catch(e){return res.status(400).json({ok:false,error:e.message});}
    }
  }
  const{data:t,error}=await db.from("traspasos").insert(fila).select().single();
  if(error||!t)return res.status(500).json({ok:false,error:"No se pudo crear el traspaso"+(error?(": "+error.message):"")});
  const N=await nombresTr(),otro=modo==="ofrecer"?para:de;
  const lista=Object.keys(prodsT).map(k=>k+"×"+prodsT[k]).join(", ");
  if(otro!=="almacen")await avisoA(otro,"↔ "+(N[yo]||yo)+(modo==="ofrecer"?" te ofrece ":" te pide ")+"mercadería"+(t.total!=null?(" por S/"+Number(t.total).toFixed(2)+" "+(PAGO_TXT[t.pago]||"")):"")+": "+lista+". Ábrelo en ↔ Traspasos.");
  await evento("traspaso","↔ Traspaso "+(modo==="ofrecer"?"ofrecido":"pedido")+(otro==="almacen"?" al almacén":""),textoTr(t,N)+(otro==="almacen"?". Te toca a ti responder desde Traspasos.":". Se mueve solo cuando los dos confirmen."),String(t.id));
  res.json({ok:true,id:t.id,cruce,total:t.total});
});
/* aceptar: el que no lo inició. Si es cruce y le toca entregar, pone precio y forma de pago */
async function aceptarTr(t,yo,b,esDueno){
  if(t.estado!=="pendiente")return {s:409,error:"Ese traspaso ya no está pendiente"};
  if(t.iniciador===yo&&!esDueno)return {s:403,error:"Lo iniciaste tú: espera que el otro lo acepte"};
  const upd={aceptado_en:new Date().toISOString()},pr=limpiaProds(t.prods);
  if(t.cruce&&(t.modo||"pedir")==="pedir"){
    const f=await faltaStock(t.de,pr);if(f)return {s:409,error:(t.de==="almacen"?"En el almacén no alcanza: ":"No tienes suficiente: ")+f};
    if(!["efectivo","yape","fiado"].includes(b.pago))return {s:400,error:"Elige la forma de pago: contado, Yape o fiado"};
    try{const p=await preciosTr(t.de,pr,b.precio_modo,b.precios);Object.assign(upd,{precio_modo:b.precio_modo,precios:p.precios,total:p.total,pago:b.pago});}
    catch(e){return {s:400,error:e.message};}
  }
  const pago=upd.pago||t.pago;
  /* fiado de mercadería del dueño a un independiente: lo aprueba el dueño (salvo que lo haya puesto él) */
  const necesita=t.cruce&&pago==="fiado"&&(await duenoDe(t.de))==="dueno"&&(await duenoDe(t.para))!=="dueno"&&!esDueno&&t.iniciador!=="almacen";
  upd.estado=necesita?"por_aprobar":"aceptado";
  await db.from("traspasos").update(upd).eq("id",t.id);Object.assign(t,upd);
  const N=await nombresTr();
  if(necesita){
    await evento("traspaso_fiado","💳 Aprobar fiado de mercadería",textoTr(t,N)+": "+(N[t.de]||t.de)+" quiere entregar tu mercadería fiada a un independiente. Apruébalo o recházalo en Traspasos.",String(t.id));
    avisarAdmin("💳 Aprobar fiado: "+textoTr(t,N)+". Revísalo en el panel → Traspasos.","credito_sin_permiso");
  }
  const otro=t.iniciador===t.de?t.de:t.para;
  if(otro!=="almacen")await avisoA(otro,"↔ "+(N[yo]||yo)+" aceptó el traspaso"+(t.total!=null?(" por S/"+Number(t.total).toFixed(2)+" "+(PAGO_TXT[t.pago]||"")):"")+(necesita?". Falta que el dueño apruebe el fiado.":". Al entregarse, confirmen los dos."));
  return {estado:t.estado,total:t.total};
}
app.post("/traspasos/:id/aceptar",authC,async(req,res)=>{
  const{data:t}=await db.from("traspasos").select("*").eq("id",req.params.id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Traspaso no encontrado"});
  const yo=req.cond.u;if(t.de!==yo&&t.para!==yo)return res.status(403).json({ok:false,error:"No es tu traspaso"});
  const r=await aceptarTr(t,yo,req.body||{},false);
  if(r.s)return res.status(r.s).json({ok:false,error:r.error});
  res.json({ok:true,estado:r.estado,total:r.total});
});
/* confirmar la entrega o la recepción (con la ubicación), rechazar o cancelar */
async function confirmarTr(t,yo,b){
  const esDe=t.de===yo,esPara=t.para===yo;
  if(["completado","rechazado","cancelado","anulado"].includes(t.estado))return {estado:t.estado};
  if(t.cruce&&!["aceptado","parcial"].includes(t.estado))
    return {s:409,error:t.estado==="por_aprobar"?"Falta que el dueño apruebe el fiado":"Primero hay que aceptarlo (precio y forma de pago) en ↔ Traspasos"};
  const upd={},ahora=new Date().toISOString();
  const pos=(b.lat!=null&&b.lon!=null&&isFinite(Number(b.lat))&&isFinite(Number(b.lon)))?{lat:Number(b.lat),lon:Number(b.lon)}:null;
  if(esDe){upd.conf_de=true;upd.conf_de_en=ahora;if(pos)upd.pos_de=pos;}
  if(esPara){upd.conf_para=true;upd.conf_para_en=ahora;if(pos)upd.pos_para=pos;}
  const cDe=upd.conf_de||t.conf_de,cPara=upd.conf_para||t.conf_para;
  await db.from("traspasos").update(Object.assign({},upd,{estado:(cDe&&cPara)?t.estado:"parcial"})).eq("id",t.id);
  Object.assign(t,upd);
  const N=await nombresTr();
  if(cDe&&cPara){
    const r=await completarTraspaso(t,N);
    if(!r.ok){await db.from("traspasos").update({estado:"parcial",[esDe?"conf_de":"conf_para"]:false}).eq("id",t.id);return {s:409,error:r.error};}
    return {estado:"completado"};
  }
  const falta=cDe?t.para:t.de;
  if(falta!=="almacen")await avisoA(falta,"↔ "+(N[yo]||yo)+" ya confirmó su parte del traspaso. Falta la tuya para que la mercadería"+(t.cruce?" y el dinero":"")+" se muevan.");
  else await evento("traspaso","↔ Falta tu confirmación en el almacén",textoTr(t,N)+": "+(N[yo]||yo)+" ya confirmó. Confírmalo en Traspasos cuando lo entregues o recibas.",String(t.id));
  return {estado:"parcial"};
}
app.post("/traspasos/estado",authC,async(req,res)=>{
  const{data:t}=await db.from("traspasos").select("*").eq("id",req.body.id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Traspaso no encontrado"});
  const yo=req.cond.u,esDe=(t.de===yo),esPara=(t.para===yo);
  if(!esDe&&!esPara)return res.status(403).json({ok:false,error:"No es tu traspaso"});
  const acc=req.body.accion||(req.body.estado==="rechazado"?"rechazar":"confirmar");
  if(acc==="rechazar"||acc==="cancelar"){
    if(["completado","rechazado","cancelado","anulado"].includes(t.estado))return res.json({ok:true,estado:t.estado});
    const est=acc==="cancelar"?"cancelado":"rechazado";
    await db.from("traspasos").update({estado:est}).eq("id",t.id);
    const N=await nombresTr(),otro=esDe?t.para:t.de;
    if(otro!=="almacen")await avisoA(otro,"✗ "+(N[yo]||yo)+(est==="cancelado"?" canceló":" rechazó")+" el traspaso.");
    await evento("traspaso","↔ Traspaso "+est,textoTr(t,N)+" ("+est+" por "+(N[yo]||yo)+")",String(t.id));
    return res.json({ok:true,estado:est});
  }
  const r=await confirmarTr(t,yo,req.body||{});
  if(r.s)return res.status(r.s).json({ok:false,error:r.error});
  res.json({ok:true,estado:r.estado});
});
/* todo lo del conductor: traspasos activos, historial, cuentas, con quién puede hacer traspasos y precios sugeridos */
app.get("/conductor/traspasos",authC,async(req,res)=>{
  res.set("Cache-Control","no-store");
  const yo=req.cond.u,hace14=new Date(Date.now()-14*86400000).toISOString();
  const[{data:act},{data:hist},{data:cs},N,st,alm,mio]=await Promise.all([
    db.from("traspasos").select("*").or(`de.eq.${yo},para.eq.${yo}`).in("estado",TR_ACT).order("id",{ascending:false}),
    db.from("traspasos").select("*").or(`de.eq.${yo},para.eq.${yo}`).in("estado",["completado","anulado","rechazado","cancelado"]).gte("creado",hace14).order("id",{ascending:false}).limit(40),
    db.from("conductores").select("usuario,nombre,tipo,activo,en_turno"),nombresTr(),leerStock(yo),leerStock("almacen"),duenoDe(yo)]);
  const act2=[];for(const t of (act||[]))act2.push(await vistaTr(t,yo,N));
  const his2=[];for(const t of (hist||[]))his2.push(await vistaTr(t,yo,N));
  /* cuentas: el independiente ve las suyas; el empleado, las del dueño (cobra o paga por él) */
  const cu=await cuentasPares(m=>m.deudor===mio||m.acreedor===mio);
  const cuentas=cu.filter(c=>c.saldo>0.004||c.a_favor>0.004).map(c=>({deudor:c.deudor,acreedor:c.acreedor,deudor_n:N[c.deudor]||c.deudor,acreedor_n:N[c.acreedor]||c.acreedor,saldo:c.saldo,
    me_deben:c.acreedor===mio,otro:c.acreedor===mio?c.deudor:c.acreedor,cargos:c.cargos.filter(g=>g.pendiente>0).map(g=>({fecha:g.fecha,detalle:g.detalle,monto:g.monto,pendiente:g.pendiente}))}));
  const ids=Object.keys(st.prods).filter(id=>Number(st.prods[id])>0);
  const uno={};ids.forEach(id=>{uno[id]=1;});
  const[cst,sug]=await Promise.all([costoPEPS(yo,uno),precioSugerido(ids)]);
  res.json({ok:true,yo,mi_dueno:mio,activos:act2,historial:his2,cuentas,
    colegas:(cs||[]).filter(c=>c.usuario!==yo&&c.activo!==false).map(c=>({u:c.usuario,n:c.nombre||c.usuario,tipo:tipoDe(c),en_viaje:!!c.en_turno})),
    mi_stock:ids.map(id=>({id,cant:Number(st.prods[id]),costo:cst[id]||0,precio:sug[id]||0})),
    almacen:Object.keys(alm.prods).filter(id=>Number(alm.prods[id])>0).map(id=>({id,cant:Number(alm.prods[id])}))});
});
/* sugerencia de precios al aceptar un pedido de otro (a costo: PEPS; a precio: catálogo) */
app.post("/conductor/traspasos/precios",authC,async(req,res)=>{
  const prods=limpiaProds(req.body.prods);const ids=Object.keys(prods);
  const[cst,sug]=await Promise.all([costoPEPS(req.cond.u,prods),precioSugerido(ids)]);
  res.json({ok:true,costo:cst,precio:sug});
});
/* cuentas entre conductores: cobrar o pagar (el empleado lo hace por el dueño) */
app.post("/conductor/cuentas/mov",authC,async(req,res)=>{
  const yo=req.cond.u,con=String(req.body.con||""),tipo=req.body.tipo==="pago"?"pago":"cobro";
  if(!quienEs(con)||con===yo)return res.status(400).json({ok:false,error:"Elige con quién"});
  const mio=await duenoDe(yo),suyo=await duenoDe(con);
  if(mio===suyo)return res.status(400).json({ok:false,error:"Entre ustedes no hay cuenta: la mercadería es del mismo dueño"});
  const deudor=tipo==="cobro"?suyo:mio,acreedor=tipo==="cobro"?mio:suyo;
  const saldo=await saldoPar(deudor,acreedor);
  let monto=r2(num(req.body.monto,0,999999,0));
  if(!(monto>0))return res.status(400).json({ok:false,error:"Escribe el monto"});
  if(saldo<=0)return res.status(409).json({ok:false,error:tipo==="cobro"?"No les debe nada":"No le deben nada"});
  if(monto>saldo)monto=saldo;
  const pago=req.body.pago==="yape"?"yape":"efectivo";
  const N=await nombresTr();
  await db.from("cuentas_mov").insert({deudor,acreedor,tipo:"abono",monto,detalle:(tipo==="cobro"?"Cobro de ":"Pago a ")+(N[con]||con)+" ("+(pago==="yape"?"Yape":"efectivo")+")",por:yo,pago});
  if(con!=="almacen")await avisoA(con,"💵 "+(N[yo]||yo)+(tipo==="cobro"?" registró que le pagaste S/":" registró que te pagó S/")+monto.toFixed(2)+" ("+(pago==="yape"?"Yape":"efectivo")+").");
  await evento("cuenta_mov","💵 Cuentas entre conductores",(N[yo]||yo)+(tipo==="cobro"?" cobró S/":" pagó S/")+monto.toFixed(2)+(tipo==="cobro"?" a ":" a ")+(N[con]||con)+" ("+(pago==="yape"?"Yape":"efectivo")+"). "+(N[deudor]||deudor)+" le debe ahora S/"+r2(saldo-monto).toFixed(2)+" a "+(N[acreedor]||acreedor)+".","");
  res.json({ok:true,monto,saldo:r2(saldo-monto)});
});
/* ═══ 185 · TRASPASOS: panel ═══ */
app.get("/admin/traspasos",authA,async(req,res)=>{
  res.set("Cache-Control","no-store");
  const hace14=new Date(Date.now()-14*86400000).toISOString();
  const[{data:act},{data:hist},N]=await Promise.all([
    db.from("traspasos").select("*").in("estado",TR_ACT).order("id",{ascending:false}).limit(200),
    db.from("traspasos").select("*").in("estado",["completado","anulado"]).gte("creado",hace14).order("id",{ascending:false}).limit(150),nombresTr()]);
  const V=async(l)=>{const o=[];for(const t of (l||[]))o.push(await vistaTr(t,"almacen",N));return o;};
  const cu=await cuentasPares(null);
  res.json({ok:true,activos:await V(act),historial:await V(hist),
    cuentas:cu.filter(c=>c.saldo>0.004||c.a_favor>0.004).map(c=>Object.assign({deudor_n:N[c.deudor]||c.deudor,acreedor_n:N[c.acreedor]||c.acreedor},c)),
    independientes:[...(await independientes())].map(u=>({u,n:N[u]||u}))});
});
app.post("/admin/traspasos/:id/aprobar",authA,async(req,res)=>{
  const{data:t}=await db.from("traspasos").select("*").eq("id",req.params.id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Traspaso no encontrado"});
  if(t.estado!=="por_aprobar")return res.status(409).json({ok:false,error:"Ese traspaso no espera aprobación"});
  const si=req.body.aprobar===true,N=await nombresTr();
  await db.from("traspasos").update({estado:si?"aceptado":"rechazado"}).eq("id",t.id);
  for(const u of [t.de,t.para])if(u!=="almacen")await avisoA(u,si?"✓ El dueño aprobó el fiado del traspaso: ya pueden entregarse y confirmar.":"✗ El dueño no aprobó el fiado del traspaso. Si quieren, háganlo al contado.");
  await db.from("logs").insert({tipo:"admin",detalle:(si?"Aprobó":"Rechazó")+" el fiado del traspaso #"+t.id+" ("+textoTr(t,N)+")"});
  res.json({ok:true,estado:si?"aceptado":"rechazado"});
});
app.post("/admin/traspasos/:id/aceptar",authA,async(req,res)=>{
  const{data:t}=await db.from("traspasos").select("*").eq("id",req.params.id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Traspaso no encontrado"});
  if(t.de!=="almacen"&&t.para!=="almacen")return res.status(400).json({ok:false,error:"Solo los traspasos con el almacén se aceptan desde el panel"});
  const r=await aceptarTr(t,"almacen",req.body||{},true);
  if(r.s)return res.status(r.s).json({ok:false,error:r.error});
  res.json({ok:true,estado:r.estado,total:r.total});
});
app.post("/admin/traspasos/:id/confirmar",authA,async(req,res)=>{
  const{data:t}=await db.from("traspasos").select("*").eq("id",req.params.id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Traspaso no encontrado"});
  if(t.de!=="almacen"&&t.para!=="almacen")return res.status(400).json({ok:false,error:"Solo confirmas el lado del almacén"});
  const r=await confirmarTr(t,"almacen",{});
  if(r.s)return res.status(r.s).json({ok:false,error:r.error});
  res.json({ok:true,estado:r.estado});
});
app.post("/admin/traspasos/:id/rechazar",authA,async(req,res)=>{
  const{data:t}=await db.from("traspasos").select("*").eq("id",req.params.id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Traspaso no encontrado"});
  if(!TR_ACT.includes(t.estado))return res.status(409).json({ok:false,error:"Ese traspaso ya terminó"});
  await db.from("traspasos").update({estado:"rechazado"}).eq("id",t.id);
  for(const u of [t.de,t.para])if(u!=="almacen")await avisoA(u,"✗ El dueño rechazó el traspaso #"+t.id+".");
  res.json({ok:true});
});
/* el almacén con un independiente: le vendes o le compras */
app.post("/admin/traspasos/nuevo",authA,async(req,res)=>{
  const b=req.body||{},con=String(b.con||"");
  if(!(await independientes()).has(con))return res.status(400).json({ok:false,error:"Elige un independiente (con tus empleados usa Almacén → enviar o pedir)"});
  const prods=limpiaProds(b.prods);if(!Object.keys(prods).length)return res.status(400).json({ok:false,error:"Elige al menos un producto"});
  const vendes=b.direccion!=="comprar",de=vendes?"almacen":con,para=vendes?con:"almacen";
  if(!["efectivo","yape","fiado"].includes(b.pago))return res.status(400).json({ok:false,error:"Elige la forma de pago"});
  if(vendes){const f=await faltaStock("almacen",prods);if(f)return res.status(409).json({ok:false,error:"En el almacén no alcanza: "+f});}
  let p;try{p=await preciosTr(de,prods,b.precio_modo,b.precios);}catch(e){return res.status(400).json({ok:false,error:e.message});}
  const{data:t,error}=await db.from("traspasos").insert({de,de_nombre:de==="almacen"?"Almacén":de,para,prods,items:await porCategoria(prods),estado:"pendiente",
    modo:vendes?"ofrecer":"pedir",iniciador:"almacen",cruce:true,precio_modo:b.precio_modo,precios:p.precios,total:p.total,pago:b.pago,nota:limpia(b.nota,200)||null}).select().single();
  if(error||!t)return res.status(500).json({ok:false,error:"No se pudo crear"+(error?(": "+error.message):"")});
  await avisoA(con,"🏬 El almacén "+(vendes?"te ofrece":"te quiere comprar")+" mercadería por S/"+p.total.toFixed(2)+" "+(PAGO_TXT[b.pago]||"")+". Acéptalo en ↔ Traspasos.");
  res.json({ok:true,id:t.id,total:p.total});
});
/* solo el dueño anula un traspaso completado: vuelve la mercadería y se deshace el dinero */
app.post("/admin/traspasos/:id/anular",authA,async(req,res)=>{
  const motivo=limpia(req.body.motivo,200);
  if(!motivo||motivo.length<4)return res.status(400).json({ok:false,error:"Escribe el motivo"});
  const{data:t}=await db.from("traspasos").select("*").eq("id",req.params.id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Traspaso no encontrado"});
  if(t.estado!=="completado")return res.status(409).json({ok:false,error:"Solo se anula un traspaso completado"});
  const pr=limpiaProds(t.prods),f=await faltaStock(t.para,pr);
  if(f)return res.status(409).json({ok:false,error:(t.para==="almacen"?"En el almacén":"Quien recibió")+" ya no tiene todo: "+f+". Coordínalo antes de anular."});
  const menos={},mas={};Object.keys(pr).forEach(id=>{menos[id]=-pr[id];mas[id]=pr[id];});
  const sal=await moverStock(t.para,menos,"traspaso_anulado",t.id);
  await moverStock(t.de,mas,"traspaso_anulado",t.id,{capas:sal.capas});
  if(t.venta_id)await db.from("ventas").update({anulada:true,nota_boleta:"ANULADA: traspaso anulado — "+motivo,editada_en:new Date().toISOString()}).eq("id",t.venta_id);
  await db.from("cuentas_mov").update({anulado:true}).eq("traspaso_id",t.id);
  await db.from("traspasos").update({estado:"anulado",anulado_en:new Date().toISOString(),anulado_por:"admin",anul_motivo:motivo}).eq("id",t.id);
  const N=await nombresTr();
  for(const u of [t.de,t.para])if(u!=="almacen")await avisoA(u,"↩️ El dueño anuló el traspaso "+textoTr(t,N)+": la mercadería vuelve a "+(N[t.de]||t.de)+(t.cruce?" y se deshace el cobro":"")+". Motivo: "+motivo);
  await db.from("logs").insert({tipo:"admin",detalle:"Anuló el traspaso #"+t.id+" ("+textoTr(t,N)+"): "+motivo});
  res.json({ok:true});
});
app.post("/admin/cuentas/mov",authA,async(req,res)=>{
  const deudor=String(req.body.deudor||""),acreedor=String(req.body.acreedor||"");
  if(deudor!=="dueno"&&acreedor!=="dueno")return res.status(400).json({ok:false,error:"Desde el panel registras lo que te pagan o lo que pagas tú"});
  const saldo=await saldoPar(deudor,acreedor);let monto=r2(num(req.body.monto,0,999999,0));
  if(!(monto>0))return res.status(400).json({ok:false,error:"Escribe el monto"});
  if(saldo<=0)return res.status(409).json({ok:false,error:"No hay deuda en esa cuenta"});
  if(monto>saldo)monto=saldo;
  const N=await nombresTr(),pago=req.body.pago==="yape"?"yape":"efectivo",otro=deudor==="dueno"?acreedor:deudor;
  await db.from("cuentas_mov").insert({deudor,acreedor,tipo:"abono",monto,detalle:(deudor==="dueno"?"Pagaste a ":"Te pagó ")+(N[otro]||otro)+" ("+(pago==="yape"?"Yape":"efectivo")+")",por:"admin",pago});
  if(otro!=="almacen")await avisoA(otro,"💵 El dueño registró "+(deudor==="dueno"?"que te pagó S/":"que le pagaste S/")+monto.toFixed(2)+".");
  res.json({ok:true,monto,saldo:r2(saldo-monto)});
});
app.post("/cargas/confirmar",authC,async(req,res)=>{
  const{data:c}=await db.from("cargas").select("*").eq("id",req.body.id).maybeSingle();
  if(c){
    await db.from("cargas").update({estado:req.body.conforme?"confirmada":"con_diferencias",items_final:catsOK(req.body.items)||c.items,motivo:req.body.motivo||""}).eq("id",c.id);
    await db.from("kardex").insert({conductor:req.cond.u,tipo:"carga_inicial",detalle:JSON.stringify(req.body.items||c.items)});
    // el detalle por producto entra al stock del camión
    const prodsCarga=(req.body.prods&&typeof req.body.prods==="object")?req.body.prods:(c.prods||null);
    if(prodsCarga)await moverStock(req.cond.u,prodsCarga,"carga",c.id,{costos:(c.detalle&&c.detalle.costos)||null});   /* 183 · lotes con el costo de la carga */
    // el turno queda abierto también al aceptar, por si se cerró o la
    // asignación no llegó a abrirlo. Si ya estaba abierto no se toca el inicio.
    const{data:yoC}=await db.from("conductores").select("en_turno,turno_ini").eq("usuario",req.cond.u).maybeSingle();
    if(!yoC||!yoC.en_turno||!yoC.turno_ini){
      await db.from("conductores").update({en_turno:true,turno_hora:new Date().toISOString(),
        turno_ini:(yoC&&yoC.turno_ini)||c.creado||new Date().toISOString()}).eq("usuario",req.cond.u);
      await db.from("logs").insert({tipo:"turno",detalle:req.cond.u+" inicia (carga aceptada)"});
    }
    if(!req.body.conforme){
      await evento("carga","📦 Carga con diferencias — "+req.cond.u,"Motivo: "+(req.body.motivo||"—"),c.id);
      avisarAdmin("📦 Carga con diferencias ("+req.cond.u+"): "+(req.body.motivo||""),"carga");
    }
  }
  res.json({ok:true});
});
app.post("/boletas",authC,async(req,res)=>{
  const{data:b}=await db.from("boletas").insert({tienda:limpia(req.body.tienda,80),tel:String(req.body.tel||"").replace(/\D/g,"").slice(0,15),
    texto:limpia(req.body.texto,1200),total:num(req.body.total,0,999999),conductor:req.cond.u,estado:"pendiente"}).select().single();
  await evento("boleta","🧾 Boleta pedida — "+req.body.tienda,"La tienda pidió comprobante (S/"+num(req.body.total,0,999999).toFixed(2)+"). Envíasela desde tu número.",b.id);
  res.json({ok:true});
});
app.get("/admin/boletas",authA,async(req,res)=>{
  const{data}=await db.from("boletas").select("*").eq("estado","pendiente").order("id",{ascending:false}).limit(50);
  res.json({ok:true,boletas:data||[]});
});
app.post("/admin/boletas/:id/enviada",authA,async(req,res)=>{
  await db.from("boletas").update({estado:"enviada"}).eq("id",req.params.id);res.json({ok:true});
});
app.post("/conductor/turno",authC,async(req,res)=>{
  const on=req.body.activo!==false;
  await db.from("logs").insert({tipo:"turno",detalle:req.cond.u+" "+(on?"inicia":"termina")});
  await db.from("conductores").update({en_turno:on,turno_hora:new Date().toISOString()}).eq("usuario",req.cond.u);
  res.json({ok:true});
});
app.post("/rutas/armada",authC,async(req,res)=>{await db.from("rutas").insert({conductor:req.cond.u,tienda:req.body.tienda,en_ruta:!!req.body.enRuta,fecha:hoy()});res.json({ok:true});});
app.post("/perdidas",authC,async(req,res)=>{
  const tipo=(req.body.tipo==="ajuste")?"ajuste":"merma";
  const motivo=limpia(req.body.motivo,40)||"otro";
  const prods=limpiaProds(req.body.prods);
  const unid=Object.keys(prods).reduce((s,k)=>s+prods[k],0);
  if(!unid)return res.status(400).json({ok:false,error:"Elige al menos un producto"});
  // valorización: precio del catálogo y costo real, calculados en el servidor
  const ids=Object.keys(prods);
  const{data:cat}=await db.from("catalogo").select("id,nombre,cat,precio,precios,costo").in("id",ids);
  const params=await getParams();
  const costosCat=params.costos||{};
  let valor=0,costo=0;const detalle=[];
  (cat||[]).forEach(p=>{
    const q=prods[p.id]||0;if(!q)return;
    const pv=Number(p.precio||0)||Number((p.precios&&Object.values(p.precios)[0])||0);
    const cu=Number(p.costo||0)||num(costosCat[p.cat],0,10000);
    valor+=pv*q;costo+=cu*q;
    detalle.push(p.nombre+" ×"+q);
  });
  /* 175 · si el dueño pidió aprobar los ajustes de conteo, el stock se mueve recién al aceptar */
  const esperaOK=tipo==="ajuste"&&!!(params.mermas_cfg&&params.mermas_cfg.ajuste_requiere_ok);
  let costoPEPS=null;
  if(!esperaOK){const mv=await moverStock(req.cond.u,Object.fromEntries(ids.map(id=>[id,-prods[id]])),tipo,null);if(mv&&mv.costo>0)costoPEPS=mv.costo;}   /* 183 */
  if(costoPEPS!=null)costo=costoPEPS;
  const fila={conductor:req.cond.u,motivo,tipo:esperaOK?"ajuste_pendiente":tipo,
    valor:Math.round(valor*100)/100,costo:Math.round(costo*100)/100,
    detalle:detalle.join(", ")+(req.body.nota?(" · "+limpia(req.body.nota,120)):""),
    tienda:limpia(req.body.tienda,60)||null,prods};
  const{data:pf,error}=await db.from("perdidas").insert(fila).select().single();
  if(error)return res.status(500).json({ok:false,error:"No se pudo registrar: "+error.message});
  if(esperaOK){
    await evento("ajuste","⚖️ Ajuste de conteo por aprobar — "+req.cond.u,unid+" unidades · "+fila.detalle+" · Motivo: "+motivo+". Si lo aceptas, se descuenta de su stock; si no, queda como estaba.",String(pf.id));
    return res.json({ok:true,pendiente:true,valor:fila.valor,costo:fila.costo,unidades:unid});
  }
  await db.from("kardex").insert({conductor:req.cond.u,tipo:tipo==="ajuste"?"ajuste":"perdida",
    detalle:motivo+" · "+unid+" unid · S/"+fila.valor.toFixed(2)+(fila.detalle?(" · "+fila.detalle):"")});
  // avisar al dueño solo cuando vale la pena
  if(tipo==="merma"&&fila.costo>=num(params.mermas_cfg&&params.mermas_cfg.aviso_desde,0,100000,30))
    await avisarAdmin("📉 Merma de "+req.cond.u+"\n"+motivo+" · "+unid+" unidades\nValor S/"+fila.valor.toFixed(2)+" (costo S/"+fila.costo.toFixed(2)+")\n"+fila.detalle,"merma",true);
  if(tipo==="ajuste")
    await avisarAdmin("⚖️ Ajuste de inventario de "+req.cond.u+"\n"+unid+" unidades · "+fila.detalle+"\nMotivo: "+motivo,"merma",true);
  res.json({ok:true,valor:fila.valor,costo:fila.costo,unidades:unid});
});
app.get("/admin/cierres",authA,async(req,res)=>{
  /* 177 · sin la foto en la lista (pesa): solo se avisa si la tiene y se pide aparte */
  const{data}=await db.from("liquidaciones").select("id,conductor,dia,kx,creado,inicio,fin,estado,efectivo_declarado,diferencia,resumen,nota,confirmada_en").order("id",{ascending:false}).limit(60);
  const ids=(data||[]).map(l=>l.id);let conFoto=new Set();
  if(ids.length){const{data:f}=await db.from("liquidaciones").select("id").in("id",ids).not("foto","is",null);conFoto=new Set((f||[]).map(x=>x.id));}
  res.json({ok:true,cierres:(data||[]).map(l=>Object.assign(l,{tiene_foto:conFoto.has(l.id)}))});
});
app.get("/admin/alertas-estado",authA,async(req,res)=>{
  let p={};try{p=await getParams();}catch(e){}
  const tel=String((p.negocio&&p.negocio.tel)||ADMIN_TEL||"").replace(/\D/g,"");
  const falta=[];
  if(!process.env.TWILIO_ACCOUNT_SID)falta.push("TWILIO_ACCOUNT_SID");
  if(!process.env.TWILIO_AUTH_TOKEN)falta.push("TWILIO_AUTH_TOKEN");
  res.json({ok:true,whatsapp:!!(twilioC&&tel),twilio:!!twilioC,telefono:!!tel,falta_en_railway:falta,
    remitente_propio:!!process.env.TWILIO_WHATSAPP_FROM});
});
app.get("/admin/cierres/:id/foto",authA,async(req,res)=>{
  const{data}=await db.from("liquidaciones").select("id,foto").eq("id",req.params.id).maybeSingle();
  if(!data||!data.foto)return res.status(404).json({ok:false,error:"Ese cierre no tiene foto"});
  res.json({ok:true,foto:data.foto});
});
app.post("/gastos",authC,async(req,res)=>{
  const p=await getParams();
  const cats=(Array.isArray(p.gasto_cats)&&p.gasto_cats.length)?p.gasto_cats:["combustible","comida","peaje","mecanico","hospedaje","otros"];
  const cat=cats.includes(req.body.categoria)?req.body.categoria:"otros";
  const monto=num(req.body.monto,0,99999);
  if(!monto)return res.status(400).json({ok:false,error:"Escribe el monto del gasto"});
  const nota=limpia(req.body.nota,160);
  /* 175 · antes el gasto solo iba al kardex, y la liquidación lee la tabla gastos:
     el gasto NUNCA se descontaba del efectivo que el conductor debía entregar */
  const{data:g,error}=await db.from("gastos").insert({conductor:req.cond.u,categoria:cat,monto,detalle:nota||null,foto:fotoOK(req.body.foto)?req.body.foto:null}).select().single();
  if(error||!g)return res.status(500).json({ok:false,error:"No se pudo guardar el gasto: "+(error?error.message:"sin respuesta de la base")});
  await db.from("kardex").insert({conductor:req.cond.u,tipo:"gasto_"+cat,detalle:"S/"+monto.toFixed(2)+(nota?" — "+nota:"")});
  /* el tope se mide en el viaje en curso (antes sumaba los últimos 120 gastos de siempre) */
  const{data:yo}=await db.from("conductores").select("turno_ini").eq("usuario",req.cond.u).maybeSingle();
  const inicio=(yo&&yo.turno_ini)||new Date(Date.now()-7*86400000).toISOString();
  const{data:gs}=await db.from("gastos").select("categoria,monto,rechazado").eq("conductor",req.cond.u).gte("creado",inicio);
  const tope=num(p.tope_gastos,0,100000)||350;
  const sum=(gs||[]).filter(x=>!x.rechazado&&x.categoria!=="combustible").reduce((s,x)=>s+Number(x.monto||0),0);
  if(sum>tope){
    await evento("gastos","💸 Gastos altos — "+req.cond.u,"Lleva S/"+sum.toFixed(2)+" en gastos que NO son combustible en este viaje (tope S/"+tope+"). Último: "+cat+" S/"+monto.toFixed(2)+(nota?" ("+nota+")":"")+". Si lo rechazas, ese gasto no se descuenta en su liquidación.",String(g.id));
    avisarAdmin("💸 "+req.cond.u+" superó el tope de gastos no-combustible: S/"+sum.toFixed(2),"gastos");
  }
  res.json({ok:true,id:g.id,acumulado_no_combustible:sum,tope});
});
/* 175 · el conductor puede anular un gasto que registró por error (solo del viaje en curso) */
app.post("/gastos/:id/anular",authC,async(req,res)=>{
  const{data:g}=await db.from("gastos").select("*").eq("id",req.params.id).eq("conductor",req.cond.u).maybeSingle();
  if(!g)return res.status(404).json({ok:false,error:"Gasto no encontrado"});
  const{data:yo}=await db.from("conductores").select("turno_ini").eq("usuario",req.cond.u).maybeSingle();
  if(yo&&yo.turno_ini&&new Date(g.creado)<new Date(yo.turno_ini))return res.status(409).json({ok:false,error:"Ese gasto es de un viaje ya liquidado: pídele al dueño que lo corrija"});
  await db.from("gastos").update({rechazado:true,nota:"Anulado por el conductor"}).eq("id",g.id);
  await db.from("kardex").insert({conductor:req.cond.u,tipo:"gasto_anulado",detalle:"S/"+Number(g.monto).toFixed(2)+" "+g.categoria});
  res.json({ok:true});
});
/* 175 · entrega parcial de efectivo al dueño durante el viaje (antes el botón no mandaba nada) */
app.post("/conductor/entrega",authC,async(req,res)=>{
  if((await independientes()).has(req.cond.u))return res.status(403).json({ok:false,error:"Los independientes no entregan efectivo al dueño: su dinero es suyo."});   /* 183 */
  const monto=num(req.body.monto,0,999999);
  if(!monto)return res.status(400).json({ok:false,error:"Escribe cuánto entregaste"});
  const{data:e,error}=await db.from("entregas").insert({conductor:req.cond.u,monto,nota:limpia(req.body.nota,160)||null}).select().single();
  if(error||!e)return res.status(500).json({ok:false,error:"No se pudo registrar la entrega: "+(error?error.message:"sin respuesta de la base")});
  await evento("entrega","💵 Entrega de efectivo por confirmar — "+req.cond.u,req.cond.u+" dice que te entregó S/"+monto.toFixed(2)+(e.nota?" ("+e.nota+")":"")+". Confírmalo cuando lo tengas en la mano; si lo rechazas, no se descuenta de su liquidación.",String(e.id));
  res.json({ok:true,id:e.id});
});
app.post("/liquidaciones",authC,async(req,res)=>{
  const u=req.cond.u;
  if((await independientes()).has(u))return res.status(403).json({ok:false,error:"Los independientes no liquidan con el dueño: cierran su viaje desde «Cerrar mi viaje»."});   /* 183 */
  {const{data:trA}=await db.from("traspasos").select("id").or(`de.eq.${u},para.eq.${u}`).in("estado",TR_ACT);
   if((trA||[]).length)return res.status(409).json({ok:false,motivo:"traspaso_activo",error:"Tienes un traspaso sin terminar: termínalo o cancélalo antes de cerrar tu viaje."});}
  // ── 1) el camión debe estar vacío ──
  const st=await leerStock(u);
  const quedan=Object.keys(st.prods).reduce((s,k)=>s+Number(st.prods[k]||0),0);
  const pCfg=await getParams();
  const permiteConStock=!!(pCfg.mermas_cfg&&pCfg.mermas_cfg.liquidar_con_stock);
  if(quedan>0&&req.body.forzar!==true&&!permiteConStock){
    const cats=await porCategoria(st.prods);
    return res.status(409).json({ok:false,motivo:"camion_con_stock",quedan,
      por_categoria:cats,
      error:"Todavía quedan "+quedan+" unidades en el camión. Déjalas en el almacén antes de liquidar."});
  }
  // ── 2) período: desde que se abrió el turno ──
  const{data:yo}=await db.from("conductores").select("turno_ini,nombre").eq("usuario",u).maybeSingle();
  const inicio=(yo&&yo.turno_ini)||new Date(Date.now()-7*86400000).toISOString();
  const fin=new Date().toISOString();
  // ── 3) todo lo que pasó en el viaje ──
  const [vts0,mov,trs,gas0,perd,crd,ent0]=await Promise.all([
    db.from("ventas").select("*").eq("conductor",u).gte("creado",inicio).lte("creado",fin),
    db.from("stock_mov").select("motivo,delta,prod_id").eq("conductor",u).gte("creado",inicio),
    db.from("traspasos").select("*").or("de.eq."+u+",para.eq."+u).gte("creado",inicio),
    db.from("gastos").select("id,categoria,monto,detalle,rechazado,creado").eq("conductor",u).gte("creado",inicio),
    db.from("perdidas").select("motivo,valor,costo,detalle,tienda,tipo,creado").eq("conductor",u).gte("creado",inicio),
    db.from("creditos_mov").select("tipo,monto,tienda_id,detalle").eq("por",u).gte("creado",inicio),
    db.from("entregas").select("id,monto,estado,nota,creado").eq("conductor",u).gte("creado",inicio)
  ]).then(r=>r.map(x=>x.data||[]));
  /* 175 · fuera: ventas anuladas y gastos rechazados; se descuenta el efectivo ya entregado al dueño */
  const vts=vts0.filter(v=>!v.anulada),gas=gas0.filter(g=>!g.rechazado),ent=ent0.filter(e=>e.estado!=="rechazada");
  const entregas=Math.round(ent.reduce((s,e)=>s+Number(e.monto||0),0)*100)/100;

  const sum=(a,f)=>a.reduce((s,x)=>s+Number(f(x)||0),0);
  const efectivo=sum(vts,v=>v.metodo==="yape"?0:v.efectivo);
  const yape=sum(vts.filter(v=>v.metodo==="yape"),v=>v.total);
  const fiado=sum(vts,v=>v.credito);
  const abonos=sum(vts,v=>v.abono);
  const gastos=sum(gas,g=>g.monto);
  const perdidas=sum(perd,p=>p.valor);
  const devueltoAlmacen=mov.filter(m=>m.motivo==="traspaso_envia").reduce((s,m)=>s+Math.abs(Number(m.delta||0)),0);
  const recibido=mov.filter(m=>m.motivo==="traspaso_recibe").reduce((s,m)=>s+Number(m.delta||0),0);
  const cargado=mov.filter(m=>m.motivo==="carga").reduce((s,m)=>s+Number(m.delta||0),0);
  const vendidoUnid=mov.filter(m=>m.motivo==="venta").reduce((s,m)=>s+Math.abs(Number(m.delta||0)),0);

  const DT=await dineroTr(u,inicio,fin);   /* 185 */
  const resumen={
    conductor:u,nombre:(yo&&yo.nombre)||u,inicio,fin,
    dias:Math.max(1,Math.round((new Date(fin)-new Date(inicio))/86400000)),
    ventas:{n:vts.length,total:sum(vts,v=>v.total),efectivo,yape,fiado,abonos},
    efectivo_esperado:Math.round((efectivo+abonos-gastos-entregas+DT.neto)*100)/100,
    traspasos_dinero:DT,   /* 185 · cobros y pagos de cuentas, compras al contado a independientes */
    entregas:{total:entregas,n:ent.length,detalle:ent},
    gastos:{total:gastos,detalle:gas},
    perdidas:(function(){
      const m=perd.filter(p=>!/^ajuste/.test(p.tipo||"")),a=perd.filter(p=>p.tipo==="ajuste");   /* 177 · pendientes y rechazados fuera */
      return{total:m.reduce((s,p)=>s+Number(p.valor||0),0),
        costo:m.reduce((s,p)=>s+Number(p.costo||0),0),
        n:m.length,detalle:m,
        ajustes:{n:a.length,detalle:a},
        por_motivo:m.reduce((r,p)=>{r[p.motivo]=(r[p.motivo]||0)+Number(p.valor||0);return r},{})};
    })(),
    mercaderia:{cargado,recibido_en_ruta:recibido,vendido:vendidoUnid,devuelto:devueltoAlmacen,queda:quedan},
    traspasos:trs.map(t=>({id:t.id,de:t.de,para:t.para,estado:t.estado,items:t.items})),
    deuda_generada:fiado,
    deuda_cobrada:abonos,
    creditos:crd
  };
  const decl=num(req.body.efectivo_declarado,0,999999);
  const dif=Math.round((decl-resumen.efectivo_esperado)*100)/100;
  const MARG=num((await getParams()).margen_liq,0,1000,5);resumen.margen=MARG;resumen.dentro_margen=Math.abs(dif)<=MARG;

  const{data:l}=await db.from("liquidaciones").insert({
    conductor:u,dia:req.body.dia||{},kx:req.body.kx||[],
    inicio,fin,estado:"pendiente",efectivo_declarado:decl,diferencia:dif,foto:fotoOK(req.body.foto)?req.body.foto:null,   /* 177 */
    resumen,nota:limpia(req.body.nota,300)||null
  }).select().single();

  // ── 4) marcar las ventas del viaje y cerrar el turno ──
  if(l){
    await db.from("ventas").update({liq_id:l.id}).eq("conductor",u).gte("creado",inicio).lte("creado",fin).is("liq_id",null);
    await db.from("conductores").update({en_turno:false,turno_hora:fin,turno_ini:null}).eq("usuario",u);
    await db.from("logs").insert({tipo:"turno",detalle:u+" termina (liquidación #"+l.id+")"});
  }
  await evento("liquidacion","💰 Liquidación de viaje — "+u,
    "Efectivo esperado S/"+resumen.efectivo_esperado.toFixed(2)+" · declarado S/"+decl.toFixed(2)+(dif?(" · diferencia S/"+dif.toFixed(2)+(Math.abs(dif)<=MARG?" (dentro del margen de S/"+MARG+")":" (fuera del margen de S/"+MARG+")")):" · cuadra")+(resumen.entregas.total?" · ya entregó S/"+resumen.entregas.total.toFixed(2)+" antes":""),l&&l.id);
  avisarAdmin("💰 Liquidación de "+u+"\nEsperado S/"+resumen.efectivo_esperado.toFixed(2)
    +"\nDeclarado S/"+decl.toFixed(2)+(dif?("\n⚠️ Diferencia S/"+dif.toFixed(2)):"\n✓ Cuadra")
    +"\nFiado en el viaje S/"+fiado.toFixed(2)+" · Cobrado S/"+abonos.toFixed(2)
    +"\nConfírmala en el panel.","liquidacion");
  res.json({ok:true,id:l&&l.id,resumen,diferencia:dif});
});
app.get("/admin/cierres/:id/ajustes",authA,async(req,res)=>{
  const{data}=await db.from("ventas").select("id,tienda,total,metodo,efectivo,credito,creado").eq("liq_id",req.params.id).eq("post_liq",true).order("id");
  const total=(data||[]).reduce((s,v)=>s+Number(v.total||0),0);
  res.json({ok:true,ventas:data||[],total});
});
app.post("/admin/cierres/:id/confirmar",authA,async(req,res)=>{
  const{error}=await db.from("liquidaciones").update({
    estado:req.body.estado==="observada"?"observada":"confirmada",
    nota:limpia(req.body.nota,300)||null,
    confirmada_en:new Date().toISOString()
  }).eq("id",req.params.id);
  if(error)return res.status(500).json({ok:false,error:error.message});
  await db.from("logs").insert({tipo:"admin",detalle:"Liquidación #"+req.params.id+" "+(req.body.estado==="observada"?"observada":"confirmada")});
  res.json({ok:true});
});
app.post("/avisos/leido",authC,async(req,res)=>{await db.from("avisos_leidos").upsert({aviso_id:req.body.id,usuario:req.cond.u});res.json({ok:true});});

// ════════ ADMINISTRADOR ════════
app.get("/admin/datos",authA,async(req,res)=>{
  const{data:us}=await db.from("conductores").select("usuario,nombre,tipo,camion,activo,pass_hash,gps_id,en_turno,turno_hora,lugares,costos");
  // quién está en turno según los logs (respaldo si la columna aún no existe)
  const turnoDe={};
  try{
    const{data:lgT}=await db.from("logs").select("detalle,creado").eq("tipo","turno").order("id",{ascending:true}).limit(400);
    (lgT||[]).forEach(l=>{
      const d=String(l.detalle||"");const u=d.split(" ")[0];
      if(u)turnoDe[u]=/inicia/.test(d);
    });
  }catch(e){}
  const{data:evs}=await db.from("eventos").select("*").eq("visto",false).order("id",{ascending:false}).limit(50);
  const{data:tds}=await db.from("tiendas").select("*").order("id");
  const{data:pds}=await db.from("pedidos").select("*").in("estado",["por_confirmar","pendiente","devuelto"]).order("id",{ascending:false}).limit(400);   /* 184 */
  const{data:vAd}=await db.from("ventas").select("tienda_id,creado,total").order("creado",{ascending:false}).limit(1200);
  const _pms=await getParams();
  const _vpt={};(vAd||[]).forEach(v=>{if(v.tienda_id)(_vpt[v.tienda_id]=_vpt[v.tienda_id]||[]).push(v);});
  /* Misma fórmula que la app del conductor: días desde la última compra buena,
     con el descuento por compras chicas y el umbral del ritmo de esa tienda.
     Antes el panel contaba días desde CUALQUIER venta, así que mostraba un
     número distinto al que veía el conductor para la misma tienda. */
  const _ritT=(t)=>ritmoDe(_pms,t.ritmo);
  const _diasT=(t)=>{const R=_ritT(t);return diasRepo(_vpt[t.id]||[],R,t.dr_ajuste,R.ciclo_dias,t.dias_atiende);};
  res.json({ok:true,
    resumen:{tiendas:(tds||[]).length,conductores:(us||[]).length,
      en_turno:(us||[]).filter(x=>(x.en_turno!==undefined&&x.en_turno!==null)?x.en_turno:turnoDe[x.usuario]).length,
      pedidos_hoy:(pds||[]).filter(p=>p.estado!=="por_confirmar"&&String(p.fecha||hoy()).slice(0,10)<=hoy()).length,
      pedidos_pendientes:(pds||[]).filter(p=>p.estado==="por_confirmar").length,
      pedidos_atrasados:(pds||[]).filter(p=>p.estado!=="por_confirmar"&&String(p.fecha||hoy()).slice(0,10)<hoy()).length},
    usuarios:(us||[]).map(u=>({usuario:u.usuario,nombre:u.nombre,tipo:tipoDe(u),lugares:lugaresDe(u),lugares_txt:resumenLugares(u),costos:(tipoDe(u)==="independiente"&&u.costos&&typeof u.costos==="object")?u.costos:{},camion:u.camion,activo:u.activo,estado:u.pass_hash?"con contraseña":"sin contraseña",gps_id:u.gps_id||"",en_turno:(u.en_turno!==undefined&&u.en_turno!==null)?!!u.en_turno:!!turnoDe[u.usuario]})),
    /* La bandeja agrupada necesita id, creado y visto; antes solo llegaban
       tipo, titulo, desc y ref, así que no podía ni ordenar ni accionar. */
    eventos:(evs||[]).map(e=>({id:e.id,tipo:e.tipo,titulo:e.titulo,
      desc:e.descripcion,descripcion:e.descripcion,
      creado:e.creado,visto:!!e.visto,
      ref:(e.tipo==="tienda_nueva"||e.tipo==="tienda_pend"||e.tipo==="correccion"||e.tipo==="ritmo_sugerido"||e.tipo==="dias_sugeridos")?e.ref:String(e.id)})),
    tiendas:(tds||[]).map(t=>{const R=_ritT(t),d=_diasT(t);return {id:t.id,cod:t.codigo||null,precios:(t.precios&&typeof t.precios==="object"&&!Array.isArray(t.precios))?t.precios:{},n_apodos:(t.apodos&&typeof t.apodos==="object")?Object.keys(t.apodos).length:0,ub:t.ubigeo||null,lugar:nombreLugar(t.ubigeo),prot:esProtegida(_pms,t.ubigeo),hab:Array.isArray(t.habilitados)?t.habilitados:[],est:t.estado_reg||"ok",dup:t.posible_dup||null,lug_manual:!!t.lug_manual,li_lugar:limiteLugar(_pms,t.ubigeo),n:t.nombre,z:t.zona,d,sa:Number(t.sa||0),cr:!!t.cr,li:Number(t.li||0),vip:!!t.vip,act:t.act,nueva:!!t.nueva,verificada:!!t.verificada,conductor:t.conductor_reg,lat:t.lat,lon:t.lon,tel:t.tel,due:t.dueno,
      ritmo:R.id,ciclo:R.ciclo_dias,nivel:nivelDe(d,R),ritmo_nom:R.nombre,ritmo_emo:R.emoji,
      dias:diasNorm(t.dias_atiende),abre_hoy:abreHoy(t.dias_atiende),dias_txt:diasTexto(t.dias_atiende),
      h_ini:t.hora_ini||"",h_fin:t.hora_fin||"",
      tp:t.tipo||"bodega",falta:[],mov:[]};}),
    ritmos:ritmosDe(_pms),
    dia_hoy:diaIdx(),dia_hoy_nom:DIA_NOM[diaIdx()],
    peso_cerrada:num((_pms.dias_cfg||{}).peso_cerrada,0,1,0.15),
    pedidos_hoy:(pds||[]).filter(p=>p.estado!=="por_confirmar").map(p=>({id:p.id,tienda:p.tienda,conductor:p.conductor,items:p.items,nota:p.nota,hora:p.hora,fecha:p.fecha})),
    params:await getParams()});
});
app.post("/admin/conductores",authA,async(req,res)=>{
  const u=String(req.body.usuario||"").toLowerCase().trim();
  if(!USR_RE.test(u))return res.status(400).json({ok:false,error:"Usuario inválido: 3-20 caracteres, minúsculas/números/_"});
  if(!req.body.nombre)return res.status(400).json({ok:false,error:"Faltan datos"});
  const{error}=await db.from("conductores").insert({usuario:u,nombre:req.body.nombre,tipo:tipoNorm(req.body.tipo),camion:req.body.camion||"—",activo:true,pass_hash:null,lugares:{}});
  if(error)return res.status(409).json({ok:false,error:"Ese usuario ya existe"});
  res.json({ok:true});
});
app.post("/admin/conductores/:u/editar",authA,async(req,res)=>{
  const upd={};
  if(req.body.nombre)upd.nombre=limpia(req.body.nombre,60);
  if(req.body.camion!=null)upd.camion=limpia(req.body.camion,20);
  if(req.body.gps_id!=null)upd.gps_id=limpia(req.body.gps_id,40)||null;
  if(req.body.tipo){   /* 181 · solo entre viajes */
    const nt=tipoNorm(req.body.tipo);
    const{data:ac}=await db.from("conductores").select("tipo").eq("usuario",req.params.u).maybeSingle();
    if(ac&&tipoDe(ac)!==nt){
      const ocupado=await enViaje(req.params.u);
      if(ocupado)return res.status(409).json({ok:false,error:"No se puede cambiar el tipo en pleno viaje: "+ocupado+". Hazlo cuando cierre su viaje."});
    }
    if(!ac||tipoDe(ac)!==nt||ac.tipo!==nt){upd.tipo=nt;INDEP.t=0;}
  }
  if(!Object.keys(upd).length)return res.json({ok:true,sin_cambios:true});
  await db.from("conductores").update(upd).eq("usuario",req.params.u);
  await db.from("logs").insert({tipo:"admin",detalle:"Editó al conductor @"+req.params.u+": "+Object.keys(upd).join(", ")});
  res.json({ok:true});
});
/* ═══ 181 · Lugares desde el panel ═══ */
app.get("/admin/lugares",authA,async(req,res)=>{
  const G=geo(),P=await getParams();
  res.set("Cache-Control","no-store").json({ok:true,falta:!!G.falta,fuente:G.fuente||"",
    dep:Object.keys(G.dep).sort().map(k=>[k,G.dep[k]]),prov:Object.keys(G.prov).sort().map(k=>[k,G.prov[k]]),
    dist:(G.dist||[]).map(d=>[d[0],d[1]]).sort((a,b)=>a[0]<b[0]?-1:1),
    protegidas:protegidas(P),limite_lugar:(P.limite_lugar&&typeof P.limite_lugar==="object")?P.limite_lugar:{},limite_credito:num(P.limite_credito,0,100000,230)});
});
app.post("/admin/lugares/config",authA,async(req,res)=>{
  const kv=await getParams(),b=req.body||{},cambios=[];
  if(Array.isArray(b.protegidas)){
    const pr=[...new Set(b.protegidas.map(String))].filter(lugarValido).slice(0,50);
    kv.protegidas=pr;cambios.push("zonas protegidas: "+(pr.length?pr.map(nombreLugar).join(" · "):"ninguna"));
  }
  if(b.limite_lugar&&typeof b.limite_lugar==="object"){
    const m={};Object.keys(b.limite_lugar).slice(0,80).forEach(p=>{if(lugarValido(p))m[p]=num(b.limite_lugar[p],0,100000,0);});
    kv.limite_lugar=m;cambios.push("límites de crédito por lugar: "+(Object.keys(m).length?Object.keys(m).map(p=>nombreLugar(p)+" S/"+m[p]).join(" · "):"ninguno"));
  }
  if(!cambios.length)return res.status(400).json({ok:false,error:"Nada que guardar"});
  const{error}=await db.from("params").upsert({id:1,kv});
  if(error)return res.status(500).json({ok:false,error:error.message});
  await db.from("logs").insert({tipo:"admin",detalle:"Lugares: "+cambios.join(" · ")});
  res.json({ok:true,protegidas:protegidas(kv),limite_lugar:kv.limite_lugar||{}});
});
app.post("/admin/conductores/:u/lugares",authA,async(req,res)=>{
  const{data:c}=await db.from("conductores").select("usuario,nombre,tipo,lugares").eq("usuario",req.params.u).maybeSingle();
  if(!c)return res.status(404).json({ok:false,error:"Conductor no encontrado"});
  const lim=a=>[...new Set((Array.isArray(a)?a:[]).map(String))].filter(lugarValido).slice(0,300);
  const L={inc:lim(req.body.inc),exc:lim(req.body.exc)};
  const{error}=await db.from("conductores").update({lugares:L}).eq("usuario",c.usuario);
  if(error)return res.status(500).json({ok:false,error:error.message});
  const txt=resumenLugares(Object.assign({},c,{lugares:L}));
  await db.from("logs").insert({tipo:"admin",detalle:"Lugares de @"+c.usuario+": "+txt});
  await avisoA(c.usuario,"📍 Tus lugares de venta cambiaron: "+txt+". Sincroniza para ver tus tiendas.");
  res.json({ok:true,lugares:L,resumen:txt});
});
app.post("/admin/tiendas/:id/lugar",authA,async(req,res)=>{
  const{data:t}=await db.from("tiendas").select("*").eq("id",req.params.id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Tienda no encontrada"});
  let ub,man;
  if(req.body.auto){ub=ubicarGPS(t.lat,t.lon);man=false;}
  else{ub=String(req.body.ubigeo||"");if(!(ub.length===6&&lugarValido(ub)))return res.status(400).json({ok:false,error:"Elige un distrito"});man=true;}
  await db.from("tiendas").update({ubigeo:ub,lug_manual:man}).eq("id",t.id);
  await db.from("logs").insert({tipo:"tienda",detalle:"#"+t.id+" "+t.nombre+" · Lugar: "+(nombreLugar(t.ubigeo)||"—")+" → "+(nombreLugar(ub)||"sin ubicar")+(man?" (corregido a mano)":" (por GPS)")});
  asegurarCodigos().catch(()=>{});   /* 184 · si aún no tenía código */
  res.json({ok:true,ubigeo:ub,lugar:nombreLugar(ub),lug_manual:man});
});
app.post("/admin/tiendas/:id/habilitados",authA,async(req,res)=>{
  const{data:t}=await db.from("tiendas").select("id,nombre,habilitados").eq("id",req.params.id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Tienda no encontrada"});
  const{data:cs}=await db.from("conductores").select("usuario,tipo");
  const ok=new Set((cs||[]).map(c=>c.usuario));
  const us=[...new Set((Array.isArray(req.body.usuarios)?req.body.usuarios:[]).map(String))].filter(u=>ok.has(u)).slice(0,50);
  await db.from("tiendas").update({habilitados:us}).eq("id",t.id);
  await db.from("logs").insert({tipo:"tienda",detalle:"#"+t.id+" "+t.nombre+" · La ven (habilitada a mano): "+(us.join(", ")||"nadie")});
  res.json({ok:true,habilitados:us});
});
app.post("/admin/lugares/recalcular",authA,async(req,res)=>{
  const n=await recalcularLugares(!!req.body.todas);
  const cods=await asegurarCodigos();   /* 184 */
  res.json({ok:true,actualizadas:n,codigos:cods});
});
/* 183 · costos propios de un independiente (lo que le cobra el proveedor a él). Tu catálogo no cambia. */
app.post("/admin/conductores/:u/costos",authA,async(req,res)=>{
  const{data:c}=await db.from("conductores").select("usuario,tipo,costos").eq("usuario",req.params.u).maybeSingle();
  if(!c)return res.status(404).json({ok:false,error:"Conductor no encontrado"});
  if(tipoDe(c)!=="independiente")return res.status(400).json({ok:false,error:"Solo los independientes tienen costos propios"});
  const m=Object.assign({},(c.costos&&typeof c.costos==="object")?c.costos:{});
  const nu=(req.body.costos&&typeof req.body.costos==="object")?req.body.costos:{};
  Object.keys(nu).slice(0,300).forEach(k=>{const id=limpia(k,40);if(!id)return;const v=num(nu[k],0,100000,0);if(v>0)m[id]=v;else delete m[id];});
  const{error}=await db.from("conductores").update({costos:m}).eq("usuario",c.usuario);
  if(error)return res.status(500).json({ok:false,error:error.message});
  res.json({ok:true,costos:m});
});
app.get("/admin/independientes",authA,async(req,res)=>{
  res.set("Cache-Control","no-store");
  const{data:cs}=await db.from("conductores").select("*");
  const ind=(cs||[]).filter(c=>tipoDe(c)==="independiente");
  const N=await nombresAcreedores();
  const out=[];
  for(const c of ind){
    const[r,{data:ci},{data:cm},{data:tr}]=await Promise.all([resumenIndep(c.usuario),
      db.from("cierres_indep").select("id,inicio,fin,resumen,efectivo_contado,diferencia,conteo").eq("conductor",c.usuario).order("id",{ascending:false}).limit(20),
      db.from("creditos_mov").select("tienda_id,tipo,monto").eq("acreedor",c.usuario),
      db.from("traspasos").select("*").or(`de.eq.${c.usuario},para.eq.${c.usuario}`).order("id",{ascending:false}).limit(20)]);
    const deu={};(cm||[]).forEach(m=>{deu[m.tienda_id]=(deu[m.tienda_id]||0)+(m.tipo==="cargo"?1:-1)*Number(m.monto||0);});
    const ids=Object.keys(deu).filter(k=>deu[k]>0.004);
    const{data:tds}=ids.length?await db.from("tiendas").select("id,nombre").in("id",ids.map(Number)):{data:[]};
    const fresco=h=>h&&(Date.now()-new Date(h).getTime())<30*60000;
    out.push({usuario:c.usuario,nombre:c.nombre,activo:c.activo,en_viaje:!!c.en_turno,lugares_txt:resumenLugares(c),
      ubicacion:c.en_turno?((fresco(c.cel_hora)&&c.lat_cel)?{lat:c.lat_cel,lon:c.lon_cel,hora:c.cel_hora}:((fresco(c.gps_hora)&&c.lat)?{lat:c.lat,lon:c.lon,hora:c.gps_hora}:null)):null,
      viaje:r,cierres:(ci||[]).map(x=>({id:x.id,inicio:x.inicio,fin:x.fin,vendido:x.resumen&&x.resumen.ventas&&x.resumen.ventas.total,costo:x.resumen&&x.resumen.ventas&&x.resumen.ventas.costo,ganancia:x.resumen&&x.resumen.ganancia,perdidas:x.resumen&&x.resumen.perdidas&&x.resumen.perdidas.costo,sobrante:x.resumen&&x.resumen.sobrante&&x.resumen.sobrante.valor,diferencia:x.diferencia,hechos:x.conteo&&x.conteo.hechos})),
      costos:(c.costos&&typeof c.costos==="object")?c.costos:{},
      credito:{total:Math.round(ids.reduce((a,k)=>a+deu[k],0)*100)/100,tiendas:(tds||[]).map(t=>({id:t.id,n:t.nombre,m:Math.round(deu[t.id]*100)/100})).sort((a,b)=>b.m-a.m)},
      traspasos:(tr||[]).map(t=>({id:t.id,de:N[t.de]||t.de,para:N[t.para]||t.para,estado:t.estado,items:t.items,creado:t.creado}))});
  }
  res.json({ok:true,independientes:out});
});
app.post("/admin/conductores/:u/reset",authA,async(req,res)=>{await db.from("conductores").update({pass_hash:null}).eq("usuario",req.params.u);
  await db.from("logs").insert({tipo:"admin",detalle:"Reseteó contraseña de @"+req.params.u});res.json({ok:true});});
app.post("/admin/conductores/:u/activo",authA,async(req,res)=>{await db.from("conductores").update({activo:!!req.body.activo}).eq("usuario",req.params.u);res.json({ok:true});});
app.post("/avisos",authA,async(req,res)=>{await avisoA((req.body.para==="todos"||USR_RE.test(req.body.para||""))?req.body.para:"todos",String(req.body.txt||""));res.json({ok:true});});
/* ═══ 184 · PEDIDOS: panel ═══ */
const vistaPedido=(p,T,N,conds,P,vig)=>{
  const t=p.tienda_id?T[p.tienda_id]:null,f=p.fecha?String(p.fecha).slice(0,10):null;
  const o={id:p.id,estado:p.estado,origen:p.origen||"panel",texto:p.texto||null,
    tienda_id:p.tienda_id||null,tienda:t?t.nombre:(p.tienda||""),codigo:(t&&t.codigo)||null,tipo:(t&&t.tipo)||null,lugar:t?nombreLugar(t.ubigeo):"",tel:(t&&t.tel)||null,
    conductor:p.conductor||null,conductor_n:p.conductor?(N[p.conductor]||p.conductor):null,
    fecha:f,fecha_txt:fechaTxt(f),lo_antes:!!p.lo_antes,visita:!!p.visita,items:Array.isArray(p.items)?p.items:[],nota:p.nota||"",hora:p.hora||"",
    creado:p.creado,confirmado_en:p.confirmado_en||null,atrasado:PED_VIG.includes(p.estado)&&!!f&&f<hoy(),
    no_pude:p.no_pude||null,atendido_por:p.atendido_por||null,atendido_por_n:p.atendido_por?(N[p.atendido_por]||p.atendido_por):null,
    atendido_en:p.atendido_en||null,vendido:p.vendido||null,detectado:p.detectado||null,
    no_abre:!!(t&&f&&!abreEl(t.dias_atiende,diaDe(f)))};
  if(p.estado!=="atendido"&&p.estado!=="entregado")o.sugeridos=sugeridosDe(t,conds,P);
  if(p.estado==="por_confirmar"){const v=(vig||[]).find(x=>x.tienda_id&&x.tienda_id===p.tienda_id);o.reemplaza=v?v.id:null;}
  return o;
};
app.get("/admin/pedidos",authA,async(req,res)=>{
  res.set("Cache-Control","no-store");
  await revisarAtrasados();   /* los atrasados llegan a la Bandeja también al abrir Pedidos */
  const ini=hoy().slice(0,8)+"01",hace14=new Date(Date.now()-14*86400000).toISOString(),hace7=Date.now()-7*86400000;
  const[{data:act},{data:hist},{data:tds},{data:cs},P,{data:mes}]=await Promise.all([
    db.from("pedidos").select("*").in("estado",["por_confirmar","pendiente","devuelto"]).order("id",{ascending:false}).limit(400),
    db.from("pedidos").select("*").in("estado",["atendido","entregado"]).gte("creado",hace14).order("id",{ascending:false}).limit(200),
    db.from("tiendas").select("id,nombre,codigo,tipo,ubigeo,tel,dueno,estado_reg,conductor_reg,habilitados,act,dias_atiende"),
    db.from("conductores").select("usuario,nombre,tipo,lugares,activo"),
    getParams(),
    db.from("pedidos").select("origen,estado").gte("creado",iniDia(ini))]);
  const T=Object.fromEntries((tds||[]).map(t=>[t.id,t])),N={};(cs||[]).forEach(c=>{N[c.usuario]=c.nombre||c.usuario;});
  const vig=(act||[]).filter(p=>p.estado!=="por_confirmar");
  const V=p=>vistaPedido(p,T,N,cs,P,vig);
  const stats={};(mes||[]).forEach(p=>{const o=p.origen||"panel";stats[o]=(stats[o]||0)+1;});
  res.json({ok:true,hoy:hoy(),ia:!!anthropic,
    por_confirmar:(act||[]).filter(p=>p.estado==="por_confirmar").map(V),
    vigentes:vig.map(V).sort((a,b)=>String(a.fecha||"").localeCompare(String(b.fecha||""))||(a.id-b.id)),
    atendidos:(hist||[]).filter(p=>new Date(p.atendido_en||p.creado).getTime()>=hace7).map(V),
    stats});
});
app.get("/admin/tiendas/:id/sugeridos",authA,async(req,res)=>{
  const[{data:t},{data:cs},P]=await Promise.all([db.from("tiendas").select("*").eq("id",req.params.id).maybeSingle(),db.from("conductores").select("usuario,nombre,tipo,lugares,activo"),getParams()]);
  if(!t)return res.status(404).json({ok:false,error:"Tienda no encontrada"});
  const{data:vg}=await db.from("pedidos").select("id,fecha,items,visita,conductor,estado").eq("tienda_id",t.id).in("estado",["pendiente","devuelto","por_confirmar"]).order("id",{ascending:false});
  res.json({ok:true,codigo:t.codigo||null,tipo:t.tipo||"bodega",sugeridos:sugeridosDe(t,cs,P),vigente:(vg||[])[0]||null});
});
/* el dueño registra un pedido: nace confirmado y le llega al conductor */
app.post("/pedidos",authA,async(req,res)=>{
  const b=req.body||{},C=await catalogoPed();
  let t=null;
  if(b.tienda_id){const{data:x}=await db.from("tiendas").select("*").eq("id",b.tienda_id).maybeSingle();t=x||null;}
  if(!t&&b.tienda){t=await tiendaPorNombre(b.tienda||"");
    if(!t){const{data:aprox}=await db.from("tiendas").select("*").ilike("nombre","%"+String(b.tienda).slice(0,20)+"%").limit(1);t=(aprox||[])[0]||null;}}
  const libre=!t?limpia(b.tienda,80):"";
  if(!t&&!libre)return res.status(400).json({ok:false,error:"Elige la tienda"});
  const conductor=limpia(b.conductor,30);
  if(!conductor)return res.status(400).json({ok:false,error:"Elige el conductor que lo atiende"});
  const{data:cd}=await db.from("conductores").select("usuario").eq("usuario",conductor).maybeSingle();
  if(!cd)return res.status(400).json({ok:false,error:"Ese conductor no existe"});
  const visita=b.visita===true,items=visita?[]:itemsPed(b.items,C);
  if(!visita&&!items.length)return res.status(400).json({ok:false,error:"Añade al menos un producto (o marca «que pase el camión»)"});
  const lo_antes=b.lo_antes===true||!fechaOK(b.fecha);
  const fecha=lo_antes?hoy():String(b.fecha);
  const origen=["panel","whatsapp","llamada","link","foto"].includes(b.origen)?b.origen:"panel";
  const{data:p,error}=await db.from("pedidos").insert({tienda_id:t?t.id:null,tienda:t?t.nombre:libre,conductor:null,items,visita,lo_antes,
    nota:limpia(b.nota,200),hora:limpia(b.hora,10)||horaPE(),fecha,estado:"por_confirmar",origen,por:"admin"}).select().single();
  if(error||!p)return res.status(500).json({ok:false,error:"No se pudo guardar el pedido"+(error?(": "+error.message):"")});
  const r=await activarPedido(p,conductor);
  res.json({ok:true,id:p.id,fecha:p.fecha,reemplazados:r.reemplazados,aviso:r.aviso});
});
app.post("/admin/pedidos/:id/confirmar",authA,async(req,res)=>{
  const b=req.body||{};
  const{data:p}=await db.from("pedidos").select("*").eq("id",req.params.id).maybeSingle();
  if(!p)return res.status(404).json({ok:false,error:"Pedido no encontrado"});
  if(p.estado!=="por_confirmar")return res.status(409).json({ok:false,error:"Ese pedido ya no está por confirmar"});
  const C=await catalogoPed();
  const tid=num(b.tienda_id,0,1e12,0)||p.tienda_id;
  const{data:t}=tid?await db.from("tiendas").select("*").eq("id",tid).maybeSingle():{data:null};
  if(!t)return res.status(400).json({ok:false,error:"Elige de qué tienda es el pedido"});
  if(t.estado_reg==="rechazada"||t.estado_reg==="fusionada"||t.act===false)return res.status(400).json({ok:false,error:"Esa tienda no está activa"});
  const conductor=limpia(b.conductor,30);
  const{data:cd}=conductor?await db.from("conductores").select("usuario").eq("usuario",conductor).maybeSingle():{data:null};
  if(!cd)return res.status(400).json({ok:false,error:"Elige el conductor que lo atiende"});
  const visita=(b.visita!==undefined)?b.visita===true:!!p.visita;
  const items=visita?[]:itemsPed(b.items!==undefined?b.items:p.items,C);
  if(!visita&&!items.length)return res.status(400).json({ok:false,error:"El pedido no tiene productos reconocidos: usa Editar"});
  const lo_antes=(b.lo_antes!==undefined)?b.lo_antes===true:!!p.lo_antes;
  const fecha=(!lo_antes&&fechaOK(b.fecha))?String(b.fecha):(p.fecha?String(p.fecha).slice(0,10):hoy());
  const upd={tienda_id:t.id,tienda:t.nombre,items,visita,lo_antes,fecha,nota:(b.nota!==undefined)?limpia(b.nota,200):(p.nota||"")};
  await db.from("pedidos").update(upd).eq("id",p.id);
  Object.assign(p,upd);
  /* apodos: lo que el dueño corrigió («choco» = Chocochispas) queda para esa tienda */
  if(b.apodos&&typeof b.apodos==="object"&&!Array.isArray(b.apodos)){
    const ap=Object.assign({},(t.apodos&&typeof t.apodos==="object"&&!Array.isArray(t.apodos))?t.apodos:{});let n=0;
    Object.keys(b.apodos).slice(0,60).forEach(k=>{const kk=claveApodo(k),id=limpia(b.apodos[k],40);if(kk.length>=2&&C.por[id]){ap[kk]=id;n++;}});
    const ks=Object.keys(ap);if(ks.length>300)ks.slice(0,ks.length-300).forEach(k=>delete ap[k]);
    if(n)await db.from("tiendas").update({apodos:ap}).eq("id",t.id);
  }
  const r=await activarPedido(p,conductor);
  res.json({ok:true,id:p.id,fecha:p.fecha,reemplazados:r.reemplazados,aviso:r.aviso});
});
app.post("/admin/pedidos/:id/descartar",authA,async(req,res)=>{
  const{data:p}=await db.from("pedidos").select("id,estado").eq("id",req.params.id).maybeSingle();
  if(!p)return res.status(404).json({ok:false,error:"Pedido no encontrado"});
  if(p.estado!=="por_confirmar")return res.status(409).json({ok:false,error:"Solo se descarta un pedido por confirmar"});
  await db.from("pedidos").update({estado:"descartado"}).eq("id",p.id);
  res.json({ok:true});
});
app.post("/admin/pedidos/:id/asignar",authA,async(req,res)=>{
  const{data:p}=await db.from("pedidos").select("*").eq("id",req.params.id).maybeSingle();
  if(!p)return res.status(404).json({ok:false,error:"Pedido no encontrado"});
  if(!PED_VIG.includes(p.estado))return res.status(409).json({ok:false,error:"Ese pedido ya no está vigente"});
  const conductor=limpia(req.body.conductor,30);
  const{data:cd}=conductor?await db.from("conductores").select("usuario").eq("usuario",conductor).maybeSingle():{data:null};
  if(!cd)return res.status(400).json({ok:false,error:"Elige el conductor"});
  const antes=p.estado==="pendiente"?p.conductor:null;
  await db.from("pedidos").update({estado:"pendiente",conductor}).eq("id",p.id);
  if(antes&&antes!==conductor)await avisoA(antes,"↩️ El pedido de «"+(p.tienda||"")+"» se le pasó a otro conductor: ya no te toca.");
  if(antes!==conductor)await avisoA(conductor,"📩 Pedido para "+fechaTxt(p.fecha)+" — «"+(p.tienda||"")+"»: "+txtItems(p.items,p.visita)+(p.nota?(" · "+p.nota):""));
  res.json({ok:true});
});
app.post("/admin/pedidos/:id/cancelar",authA,async(req,res)=>{
  const{data:p}=await db.from("pedidos").select("*").eq("id",req.params.id).maybeSingle();
  if(!p)return res.status(404).json({ok:false,error:"Pedido no encontrado"});
  if(!PED_VIG.includes(p.estado))return res.status(409).json({ok:false,error:"Ese pedido ya no está vigente"});
  await db.from("pedidos").update({estado:"cancelado",nota:limpia((p.nota?p.nota+" · ":"")+"Cancelado: "+(req.body.motivo||"por el dueño"),200)}).eq("id",p.id);
  if(p.estado==="pendiente"&&p.conductor)await avisoA(p.conductor,"✕ Se canceló el pedido de «"+(p.tienda||"")+"». Ya no hace falta llevarlo.");
  res.json({ok:true});
});
/* camino 1: pegar o dictar (o foto). La IA (o la lectura simple) arma el pedido y queda «por confirmar» */
app.post("/admin/pedidos/interpretar",authA,async(req,res)=>{
  const texto=String(req.body.texto==null?"":req.body.texto).replace(/[<>`]/g,"").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g," ").trim().slice(0,4000);
  const img=String(req.body.imagen||"");
  const m=img?img.match(/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/):null;
  if(img&&!m)return res.status(400).json({ok:false,error:"Imagen inválida (usa una foto JPG o PNG)"});
  if(!texto&&!m)return res.status(400).json({ok:false,error:"Pega el mensaje, escribe lo que te dijeron o sube la foto"});
  if(m&&!anthropic)return res.json({ok:false,error:"Para leer fotos hace falta ANTHROPIC_API_KEY en Railway. Mientras tanto, escribe el pedido."});
  const origen=["whatsapp","llamada","foto"].includes(req.body.origen)?req.body.origen:(m?"foto":"whatsapp");
  const C=await catalogoPed();
  const{data:tds0}=await db.from("tiendas").select("id,nombre,codigo,dueno,tel,apodos,estado_reg,act,tipo");
  const tds=(tds0||[]).filter(t=>t.act!==false&&!["rechazada","fusionada"].includes(t.estado_reg||"ok"));
  const fija=num(req.body.tienda_id,0,1e12,0)?tds.find(t=>t.id===Number(req.body.tienda_id))||null:null;
  let det=null,falloIA=null;
  if(anthropic){try{det=await leerPedidoIA(texto,m,C,fija?[fija]:tds);det.metodo="ia";}catch(e){falloIA=e.message;console.log("IA pedido:",e.message);}}
  if(!det){
    if(!texto)return res.json({ok:false,error:"No se pudo leer la foto"+(falloIA?(": "+falloIA):"")});
    det=leerPedidoSimple(texto,C,fija?[fija]:tds);det.metodo="simple";if(falloIA)det.dudas="La IA falló ("+falloIA+"). "+det.dudas;
  }
  const t=fija||(det.tienda_id?tds.find(x=>x.id===det.tienda_id)||null:null);
  const ap=(t&&t.apodos&&typeof t.apodos==="object")?t.apodos:{};
  det.lineas=(det.lineas||[]).map(l=>{const k=claveApodo(l.texto);return (k&&ap[k]&&C.por[ap[k]])?Object.assign({},l,{id:ap[k],apodo:true}):l;});
  const items=[];det.lineas.forEach(l=>{if(l.id&&C.por[l.id]){const e=items.find(x=>x.id===l.id);if(e)e.c=Math.min(999,e.c+l.c);else items.push({id:l.id,n:C.por[l.id].nombre,c:l.c});}});
  const f=(fechaOK(det.fecha)&&det.fecha>=hoy())?det.fecha:hoy();
  const{data:p,error}=await db.from("pedidos").insert({tienda_id:t?t.id:null,tienda:t?t.nombre:(det.tienda_texto||""),items,visita:!!det.visita&&!items.length,
    fecha:f,lo_antes:!fechaOK(det.fecha),nota:limpia(det.nota,200),texto:texto||"(foto)",hora:horaPE(),estado:"por_confirmar",origen,por:"admin",
    detectado:{metodo:det.metodo,lineas:det.lineas,tienda_texto:det.tienda_texto||"",dudas:det.dudas||""}}).select().single();
  if(error||!p)return res.status(500).json({ok:false,error:"No se pudo guardar"+(error?(": "+error.message):"")});
  res.json({ok:true,id:p.id,metodo:det.metodo,tienda:t?t.nombre:null,lineas:det.lineas.length,reconocidas:det.lineas.filter(l=>l.id).length});
});
/* link de pedido: clave larga al azar, un solo uso, vence a las 2 horas */
app.post("/admin/tiendas/:id/link-pedido",authA,async(req,res)=>{
  const{data:t}=await db.from("tiendas").select("*").eq("id",req.params.id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Tienda no encontrada"});
  if(t.estado_reg&&t.estado_reg!=="ok")return res.status(400).json({ok:false,error:"Primero aprueba la tienda"});
  const clave=cryptoR.randomBytes(18).toString("base64url");
  const vence=new Date(Date.now()+2*3600000).toISOString();
  const{error}=await db.from("pedido_links").insert({clave,tienda_id:t.id,vence});
  if(error)return res.status(500).json({ok:false,error:"No se pudo crear el link: "+error.message});
  const base=String(process.env.URL_PUBLICA||(req.protocol+"://"+req.get("host"))).replace(/\/+$/,"");
  const url=base+"/p/"+clave,P=await getParams();
  const neg=(P.negocio&&P.negocio.nombre)||"tu distribuidor";
  const msg="Hola"+(t.dueno?(" "+t.dueno):"")+", para hacer tu pedido a "+neg+" entra aquí: "+url+" (sirve una sola vez y dura 2 horas)";
  const tel=telPE(t.tel);
  res.json({ok:true,url,msg,vence,wa:tel?("https://wa.me/"+tel+"?text="+encodeURIComponent(msg)):null,sin_tel:!tel});
});
/* precios acordados: el dueño los ve y los quita (la tienda vuelve al precio de su tipo) */
app.post("/admin/tiendas/:id/precios",authA,async(req,res)=>{
  const{data:t}=await db.from("tiendas").select("id,nombre,precios").eq("id",req.params.id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Tienda no encontrada"});
  let pr=Object.assign({},(t.precios&&typeof t.precios==="object"&&!Array.isArray(t.precios))?t.precios:{});
  if(req.body.todos===true)pr={};
  else (Array.isArray(req.body.quitar)?req.body.quitar:[]).forEach(id=>{delete pr[String(id)];});
  await db.from("tiendas").update({precios:pr}).eq("id",t.id);
  await db.from("logs").insert({tipo:"admin",detalle:"Precios acordados de «"+t.nombre+"»: "+(req.body.todos===true?"quitó todos":("quitó "+(req.body.quitar||[]).length)) });
  res.json({ok:true,precios:pr});
});
/* ═══ 184 · LINK DE PEDIDO: la página que abre la tienda (sin sesión, sin precios) ═══ */
const PAGINA_PEDIDO="<!doctype html>\n<html lang=\"es\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">\n<meta name=\"robots\" content=\"noindex,nofollow\"><title>Hacer mi pedido</title>\n<style>\n:root{--bg:#F6F3EC;--card:#fff;--tx:#1F2420;--mu:#6B7068;--bd:#E2DDD2;--ac:#1D4ED8;--acl:#EBF1FE;--ok:#2F6B4F;--okl:#EAF5EE;--wa:#B97A1F;--wal:#FBF3E4}\n@media (prefers-color-scheme:dark){:root{--bg:#141714;--card:#1E221E;--tx:#EDEDE8;--mu:#A2A79E;--bd:#343A33;--ac:#7FA3FF;--acl:#1F2A44;--ok:#7FC79E;--okl:#1D2D23;--wa:#E0B060;--wal:#33291A}}\n*{box-sizing:border-box}\nbody{margin:0;background:var(--bg);color:var(--tx);font:15px/1.45 system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif;padding:16px 16px 120px}\n.w{max-width:520px;margin:0 auto}\nh1{font-size:20px;margin:6px 0 2px}\n.sub{color:var(--mu);font-size:13px;margin-bottom:14px}\n.c{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:14px;margin-bottom:12px}\n.op{display:block;width:100%;text-align:left;background:var(--card);border:2px solid var(--bd);border-radius:14px;padding:16px;margin-bottom:10px;color:var(--tx);font:inherit;cursor:pointer}\n.op b{display:block;font-size:16px;margin-bottom:3px}.op span{color:var(--mu);font-size:13px}\n.op:active{border-color:var(--ac)}\n.chips{display:flex;gap:6px;overflow-x:auto;padding-bottom:6px;margin-bottom:8px;-webkit-overflow-scrolling:touch}\n.chip{flex:none;border:1.5px solid var(--bd);background:var(--card);color:var(--tx);border-radius:18px;padding:8px 12px;font:600 13px system-ui;cursor:pointer}\n.chip.on{border-color:var(--ac);background:var(--acl);color:var(--ac)}\n.fila{display:flex;align-items:center;gap:8px;padding:10px 0;border-bottom:1px solid var(--bd)}\n.fila:last-child{border-bottom:none}\n.fila .n{flex:1;font-size:14.5px}\n.fila .n.si{font-weight:800}\n.bq{width:40px;height:40px;border-radius:11px;border:1.5px solid var(--bd);background:var(--card);color:var(--tx);font:800 20px system-ui;cursor:pointer}\n.bq.mas{border-color:var(--ac);background:var(--acl);color:var(--ac)}\n.q{min-width:30px;text-align:center;font-weight:800;font-size:16px}\n.barra{position:fixed;left:0;right:0;bottom:0;background:var(--card);border-top:1px solid var(--bd);padding:12px 16px calc(12px + env(safe-area-inset-bottom))}\n.barra .w{display:flex;gap:10px;align-items:center}\n.btn{flex:1;border:none;border-radius:12px;padding:14px;font:800 15px system-ui;background:var(--ac);color:#fff;cursor:pointer}\n.btn.sec{background:none;border:1.5px solid var(--bd);color:var(--tx);flex:none;padding:14px 16px}\n.btn:disabled{opacity:.45}\n.dia{display:inline-block;border:1.5px solid var(--bd);border-radius:12px;padding:10px 12px;margin:0 6px 8px 0;background:var(--card);color:var(--tx);font:600 14px system-ui;cursor:pointer}\n.dia.on{border-color:var(--ac);background:var(--acl);color:var(--ac)}\n.dia small{display:block;font-weight:500;font-size:11px;color:var(--mu)}\n.ok{background:var(--okl);border-color:transparent;color:var(--ok)}\n.aviso{background:var(--wal);color:var(--wa);border-radius:12px;padding:12px;font-size:13.5px}\n.li{padding:7px 0;border-bottom:1px solid var(--bd);display:flex;justify-content:space-between}\n.li:last-child{border-bottom:none}\ninput[type=search]{width:100%;padding:12px;border-radius:12px;border:1.5px solid var(--bd);background:var(--card);color:var(--tx);font-size:16px;margin-bottom:8px}\n</style></head>\n<body><div class=\"w\" id=\"app\"><div class=\"c\">Cargando…</div></div>\n<div class=\"barra\" id=\"barra\" style=\"display:none\"><div class=\"w\" id=\"barra-w\"></div></div>\n<script>\n(function(){\nvar D=null,MODO=null,PASO='elegir',Q={},CAT=0,CUANDO=null,BUSCA='',ENVIANDO=false;\nvar $=function(id){return document.getElementById(id)};\nfunction esc(s){return String(s==null?'':s).replace(/[&<>\"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]})}\nvar base=location.pathname.replace(/\\/+$/,'');\nfunction barra(h){var b=$('barra');if(!h){b.style.display='none';return;}$('barra-w').innerHTML=h;b.style.display='block';}\nfunction pinta(h){$('app').innerHTML=h;window.scrollTo(0,0);}\nfunction cab(){return '<h1>Pedido para '+esc(D.tienda)+'</h1><div class=\"sub\">'+esc(D.negocio||'')+'</div>';}\nfunction prods(){var o=[];(D.cats||[]).forEach(function(c){(c.prods||[]).forEach(function(p){o.push({id:p.id,n:p.n,cat:c})})});return o;}\nfunction elegidos(){return prods().filter(function(p){return Q[p.id]>0});}\nfunction total(){return elegidos().reduce(function(a,p){return a+Q[p.id]},0);}\nfunction listaPedido(items,visita){\n if(visita)return '<div class=\"li\"><span>🚚 Que pase el camión: eliges al verlo</span></div>';\n return (items||[]).map(function(x){return '<div class=\"li\"><span>'+esc(x.n)+'</span><b>'+x.c+'</b></div>'}).join('');\n}\nfunction cuandoTxt(f,asap){if(asap)return 'Lo antes posible';var d=(D.dias||[]).find(function(x){return x.f===f});return d?d.n:f;}\nfunction render(){\n if(!D)return;\n if(D.estado==='vencido'){barra(null);return pinta(cab()+'<div class=\"c aviso\">Este link ya venció (dura 2 horas). Pídele uno nuevo a tu distribuidor.</div>');}\n if(D.estado==='usado'){barra(null);var p=D.pedido||{};\n  return pinta(cab()+'<div class=\"c ok\"><b>✅ Pedido enviado</b><div style=\"font-size:13px;margin-top:3px\">Tu distribuidor lo revisa y te lo lleva. Este link ya no se puede usar otra vez.</div></div>'\n   +'<div class=\"c\"><div style=\"font-size:12px;color:var(--mu);margin-bottom:6px\">Para: '+esc(cuandoTxt(p.fecha,p.lo_antes))+'</div>'+listaPedido(p.items,p.visita)+'</div>');}\n if(PASO==='elegir'){barra(null);\n  return pinta(cab()+'<div class=\"sub\">¿Cómo quieres pedir?</div>'\n   +'<button class=\"op\" onclick=\"PED.modo(\\'visita\\')\"><b>🚚 Que pase el camión</b><span>Eliges los productos cuando llegue.</span></button>'\n   +'<button class=\"op\" onclick=\"PED.modo(\\'productos\\')\"><b>📝 Escoger productos ahora</b><span>Marca lo que necesitas y cuántos.</span></button>');}\n if(PASO==='productos'){\n  var cs=D.cats||[];if(CAT>=cs.length)CAT=0;var c=cs[CAT]||{prods:[]};\n  var lista=BUSCA?prods().filter(function(p){return p.n.toLowerCase().indexOf(BUSCA.toLowerCase())>=0}):(c.prods||[]).map(function(p){return {id:p.id,n:p.n}});\n  pinta(cab()+'<input type=\"search\" placeholder=\"Buscar producto…\" value=\"'+esc(BUSCA)+'\" oninput=\"PED.busca(this.value)\" id=\"busca\">'\n   +(BUSCA?'':'<div class=\"chips\">'+cs.map(function(x,i){return '<button class=\"chip'+(i===CAT?' on':'')+'\" onclick=\"PED.cat('+i+')\">'+esc((x.emoji||'')+' '+x.nom)+'</button>'}).join('')+'</div>')\n   +'<div class=\"c\" style=\"padding:4px 14px\">'+(lista.length?lista.map(function(p){var q=Q[p.id]||0;\n     return '<div class=\"fila\"><div class=\"n'+(q?' si':'')+'\">'+esc(p.n)+'</div><button class=\"bq\" onclick=\"PED.q(\\''+p.id+'\\',-1)\" aria-label=\"menos\">−</button><span class=\"q\">'+q+'</span><button class=\"bq mas\" onclick=\"PED.q(\\''+p.id+'\\',1)\" aria-label=\"más\">+</button></div>'}).join(''):'<div style=\"padding:12px 0;color:var(--mu)\">No hay productos con ese nombre.</div>')+'</div>');\n  if(BUSCA){var b=$('busca');if(b){b.focus();b.setSelectionRange(b.value.length,b.value.length);}}\n  var n=elegidos().length;\n  barra('<button class=\"btn sec\" onclick=\"PED.volver()\">Atrás</button><button class=\"btn\" '+(n?'':'disabled')+' onclick=\"PED.revisar()\">'+(n?('Continuar · '+n+' producto'+(n>1?'s':'')):'Elige productos')+'</button>');\n  return;}\n if(PASO==='revisar'){\n  pinta(cab()+'<div class=\"c\"><b>¿Es todo?</b><div style=\"margin-top:8px\">'+listaPedido(elegidos().map(function(p){return {n:p.n,c:Q[p.id]}}))+'</div></div>');\n  barra('<button class=\"btn sec\" onclick=\"PED.paso(\\'productos\\')\">Añadir más</button><button class=\"btn\" onclick=\"PED.paso(\\'cuando\\')\">Sí, es todo</button>');return;}\n if(PASO==='cuando'){\n  pinta(cab()+'<div class=\"c\"><b>¿Para cuándo?</b><div style=\"margin-top:10px\">'\n   +'<button class=\"dia'+(CUANDO==='asap'?' on':'')+'\" onclick=\"PED.cuando(\\'asap\\')\">Lo antes posible</button>'\n   +(D.dias||[]).map(function(d){return '<button class=\"dia'+(CUANDO===d.f?' on':'')+'\" onclick=\"PED.cuando(\\''+d.f+'\\')\">'+esc(d.n)+(d.cerrado?'<small>no atiendes</small>':'')+'</button>'}).join('')\n   +'</div></div>'+(MODO==='visita'?'<div class=\"c\">'+listaPedido([],true)+'</div>':'<div class=\"c\">'+listaPedido(elegidos().map(function(p){return {n:p.n,c:Q[p.id]}}))+'</div>'));\n  barra('<button class=\"btn sec\" onclick=\"PED.paso(\\''+(MODO==='visita'?'elegir':'revisar')+'\\')\">Atrás</button><button class=\"btn\" '+(CUANDO&&!ENVIANDO?'':'disabled')+' onclick=\"PED.enviar()\">'+(ENVIANDO?'Enviando…':'Confirmar pedido')+'</button>');return;}\n}\nwindow.PED={\n modo:function(m){MODO=m;CUANDO=null;PASO=(m==='visita')?'cuando':'productos';render();},\n cat:function(i){CAT=i;render();},\n busca:function(v){BUSCA=v;render();},\n q:function(id,d){Q[id]=Math.max(0,Math.min(999,(Q[id]||0)+d));if(!Q[id])delete Q[id];render();},\n volver:function(){PASO='elegir';render();},\n revisar:function(){PASO='revisar';render();},\n paso:function(p){PASO=p;render();},\n cuando:function(c){CUANDO=c;render();},\n enviar:async function(){\n  if(ENVIANDO||!CUANDO)return;ENVIANDO=true;render();\n  var items={};elegidos().forEach(function(p){items[p.id]=Q[p.id]});\n  try{\n   var r=await fetch(base+'/enviar',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({modo:MODO,items:MODO==='visita'?{}:items,cuando:CUANDO})});\n   var j=await r.json();\n   if(j&&j.ok){D.estado='usado';D.pedido=j.pedido;ENVIANDO=false;render();return;}\n   ENVIANDO=false;alert((j&&j.error)||'No se pudo enviar. Inténtalo de nuevo.');\n   if(j&&(j.estado==='usado'||j.estado==='vencido'))cargar();else render();\n  }catch(e){ENVIANDO=false;alert('Sin conexión. Revisa tu internet e inténtalo de nuevo.');render();}\n }\n};\nasync function cargar(){\n try{var r=await fetch(base+'/datos',{cache:'no-store'});var j=await r.json();\n  if(!j||!j.ok){pinta('<div class=\"c aviso\">Este link no existe. Pídele uno nuevo a tu distribuidor.</div>');return;}\n  D=j;render();\n }catch(e){pinta('<div class=\"c aviso\">Sin conexión. Revisa tu internet y vuelve a abrir el link.</div>');}\n}\ncargar();\n})();\n</script></body></html>\n";
async function linkDe(clave){
  clave=String(clave||"");if(!/^[A-Za-z0-9_-]{16,64}$/.test(clave))return null;
  const{data}=await db.from("pedido_links").select("*").eq("clave",clave).maybeSingle();
  return data||null;
}
app.get("/p/:clave",(req,res)=>{res.set("Cache-Control","no-store");res.set("X-Robots-Tag","noindex");res.type("html").send(PAGINA_PEDIDO);});
app.get("/p/:clave/datos",async(req,res)=>{
  res.set("Cache-Control","no-store");
  const L=await linkDe(req.params.clave);
  if(!L)return res.status(404).json({ok:false,estado:"no_existe"});
  const[{data:t},P]=await Promise.all([db.from("tiendas").select("id,nombre,tipo,dias_atiende").eq("id",L.tienda_id).maybeSingle(),getParams()]);
  if(!t)return res.status(404).json({ok:false,estado:"no_existe"});
  const base={ok:true,tienda:t.nombre,negocio:(P.negocio&&P.negocio.nombre)||""};
  if(L.usado_en){
    const{data:p}=L.pedido_id?await db.from("pedidos").select("items,visita,fecha,lo_antes").eq("id",L.pedido_id).maybeSingle():{data:null};
    return res.json(Object.assign(base,{estado:"usado",pedido:p?{items:(p.items||[]).map(x=>({n:x.n||x.p,c:x.c})),visita:!!p.visita,fecha:p.fecha?String(p.fecha).slice(0,10):null,lo_antes:!!p.lo_antes}:null}));
  }
  if(new Date(L.vence).getTime()<Date.now())return res.json(Object.assign(base,{estado:"vencido"}));
  const C=await catalogoPed(),tipo=t.tipo||"bodega";
  const cats=C.cats.map(c=>({id:c.id,nom:String(c.nom||"").replace(/^[^\wáéíóúñÁÉÍÓÚÑ]+\s*/,""),emoji:c.emoji||"",
    prods:C.prods.filter(p=>p.cat===c.id&&!(Array.isArray(p.no_tipos)&&p.no_tipos.includes(tipo))).map(p=>({id:p.id,n:p.nombre}))})).filter(c=>c.prods.length);
  const dias=[];for(let i=0;i<7;i++){const f=sumarDias(hoy(),i);dias.push({f,n:i===0?"Hoy":(i===1?"Mañana":(DIA_NOM[diaDe(f)].charAt(0).toUpperCase()+DIA_NOM[diaDe(f)].slice(1)+" "+Number(f.slice(8,10)))),cerrado:!abreEl(t.dias_atiende,diaDe(f))||undefined});}
  res.json(Object.assign(base,{estado:"nuevo",vence:L.vence,cats,dias}));
});
app.post("/p/:clave/enviar",async(req,res)=>{
  const L=await linkDe(req.params.clave);
  if(!L)return res.status(404).json({ok:false,estado:"no_existe",error:"Este link no existe"});
  if(L.usado_en)return res.status(409).json({ok:false,estado:"usado",error:"Este link ya se usó"});
  if(new Date(L.vence).getTime()<Date.now())return res.status(410).json({ok:false,estado:"vencido",error:"Este link ya venció. Pide uno nuevo."});
  const{data:t}=await db.from("tiendas").select("id,nombre,tipo,codigo").eq("id",L.tienda_id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,estado:"no_existe",error:"Este link no existe"});
  const visita=req.body.modo==="visita",C=await catalogoPed(),tipo=t.tipo||"bodega";
  const its=[];
  if(!visita&&req.body.items&&typeof req.body.items==="object")Object.keys(req.body.items).slice(0,150).forEach(id=>{
    const p=C.por[id];if(!p||(Array.isArray(p.no_tipos)&&p.no_tipos.includes(tipo)))return;
    const c=Math.round(num(req.body.items[id],0,999,0));if(c>0)its.push({id,n:p.nombre,c});});
  if(!visita&&!its.length)return res.status(400).json({ok:false,error:"Elige al menos un producto"});
  const cu=String(req.body.cuando||"");
  const asap=cu==="asap"||!fechaOK(cu)||cu<hoy();
  const fecha=asap?hoy():(cu>sumarDias(hoy(),30)?sumarDias(hoy(),30):cu);
  /* un solo uso: se marca antes de crear el pedido; si otro envío ganó, este no sigue */
  const ahora=new Date().toISOString();
  const{data:marc}=await db.from("pedido_links").update({usado_en:ahora}).eq("id",L.id).is("usado_en",null).select();
  if(!marc||!marc.length)return res.status(409).json({ok:false,estado:"usado",error:"Este link ya se usó"});
  const{data:p,error}=await db.from("pedidos").insert({tienda_id:t.id,tienda:t.nombre,items:its,visita,fecha,lo_antes:asap,hora:horaPE(),estado:"por_confirmar",origen:"link",por:"tienda"}).select().single();
  if(error||!p){await db.from("pedido_links").update({usado_en:null}).eq("id",L.id);return res.status(500).json({ok:false,error:"No se pudo enviar el pedido. Inténtalo de nuevo."});}
  await db.from("pedido_links").update({pedido_id:p.id}).eq("id",L.id);
  await evento("pedido_nuevo","📩 Pedidos por confirmar",t.nombre+(t.codigo?(" ("+t.codigo+")"):"")+" pidió por link para "+(asap?"lo antes posible":fechaTxt(fecha))+": "+txtItems(its,visita)+". Confírmalo en Pedidos.",String(p.id));
  res.json({ok:true,pedido:{items:its.map(x=>({n:x.n,c:x.c})),visita,fecha,lo_antes:asap}});
});
/* ═══ 184 · PEDIDOS: conductor ═══ */
app.post("/conductor/pedidos/:id/no-pude",authC,async(req,res)=>{
  const{data:p}=await db.from("pedidos").select("*").eq("id",req.params.id).maybeSingle();
  if(!p)return res.status(404).json({ok:false,error:"Pedido no encontrado"});
  if(p.estado!=="pendiente"||p.conductor!==req.cond.u)return res.json({ok:true,ya:true});
  const motivo=limpia(req.body.motivo,120)||"sin motivo";
  const{data:yo}=await db.from("conductores").select("nombre").eq("usuario",req.cond.u).maybeSingle();
  await db.from("pedidos").update({estado:"devuelto",conductor:null,no_pude:{por:req.cond.u,motivo,en:new Date().toISOString()}}).eq("id",p.id);
  await evento("pedido_no_pude","↩️ Pedidos que no se pudieron entregar",((yo&&yo.nombre)||req.cond.u)+" no pudo entregar el pedido de «"+(p.tienda||"")+"» ("+txtItems(p.items,p.visita)+"): "+motivo+". Reasígnalo en Pedidos.",String(p.id));
  res.json({ok:true});
});
app.post("/admin/cargas/leer",authA,async(req,res)=>{
  if(!anthropic)return res.json({ok:false,error:"Falta ANTHROPIC_API_KEY en Railway para leer imágenes."});
  const img=String(req.body.imagen||"");
  const m=img.match(/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/);
  if(!m)return res.json({ok:false,error:"Imagen inválida (usa foto JPG/PNG del documento)"});
  if(m[2].length>7000000)return res.json({ok:false,error:"Imagen muy pesada: reduce la calidad"});
  const catalogo=Array.isArray(req.body.catalogo)?req.body.catalogo.slice(0,400):[];
  try{
    const r=await anthropic.messages.create({model:MODELO_IA,max_tokens:2000,
      system:"Eres un asistente que lee documentos de carga de una distribuidora peruana de panes y pasteles. Devuelve SOLO JSON válido, sin markdown ni explicación.",
      messages:[{role:"user",content:[
        {type:"image",source:{type:"base64",media_type:m[1],data:m[2]}},
        {type:"text",content:undefined,text:"Lee las cantidades de este documento de carga. Esta es la lista oficial de productos (id | nombre | categoria):\n"+
          catalogo.map(p=>`${p.id} | ${p.nombre} | ${p.cat}`).join("\n")+
          "\n\nDevuelve JSON: {\"items\":[{\"id\":\"<id del catálogo o null>\",\"texto\":\"<como aparece en el documento>\",\"cantidad\":<número>,\"confianza\":\"alta|media|baja\"}],\"no_reconocido\":[\"<líneas que no pudiste asociar>\"]}\nReglas: usa SOLO ids de la lista; si una línea no calza con ninguno, ponla en no_reconocido; no inventes productos ni cantidades; si la cantidad no se lee claro, marca confianza baja."}]}]});
    const txt=(r.content||[]).filter(x=>x.type==="text").map(x=>x.text).join("").replace(/```json|```/g,"").trim();
    let j;try{j=JSON.parse(txt)}catch(e){return res.json({ok:false,error:"No pude interpretar el documento. Prueba con una foto más nítida."})}
    const ids=new Set(catalogo.map(p=>p.id));
    const items=(j.items||[]).filter(x=>x&&ids.has(x.id)).map(x=>({id:x.id,texto:String(x.texto||"").slice(0,60),cantidad:num(x.cantidad,0,99999),confianza:["alta","media","baja"].includes(x.confianza)?x.confianza:"media"}));
    res.json({ok:true,items,no_reconocido:(j.no_reconocido||[]).slice(0,30).map(s=>String(s).slice(0,60))});
  }catch(e){res.json({ok:false,error:"Error al leer: "+e.message});}
});
app.post("/cargas",authA,async(req,res)=>{
  const cond=String(req.body.conductor||"").trim();
  if(!USR_RE.test(cond))return res.status(400).json({ok:false,error:"Elige el conductor antes de asignar la carga"});
  const{data:ex}=await db.from("conductores").select("usuario").eq("usuario",cond).maybeSingle();
  if(!ex)return res.status(400).json({ok:false,error:"Ese conductor no existe: "+cond});
  const items=catsOK(req.body.items);
  if(!items)return res.status(400).json({ok:false,error:"La carga no tiene productos"});
  const prods=(req.body.prods&&typeof req.body.prods==="object"&&Object.keys(req.body.prods).length)?req.body.prods:null;
  /* 178 · la carga se valoriza al COSTO de compra (lo que pagaste al proveedor), no al
     precio de venta: la ganancia sale después, de lo que se venda. Se guarda el costo de
     ese momento para que un cambio de costo posterior no cambie cargas pasadas. */
  let detalle=(req.body.detalle&&typeof req.body.detalle==="object"&&!Array.isArray(req.body.detalle))?req.body.detalle:{};
  let valorCosto=0;const sinCosto=[];
  if(prods){
    const ids=Object.keys(prods);
    const[{data:cps},pC,{data:cI}]=await Promise.all([db.from("catalogo").select("id,cat,costo").in("id",ids),getParams(),db.from("conductores").select("tipo,costos").eq("usuario",cond).maybeSingle()]);
    const cc=(pC&&pC.costos)||{},snap={};
    /* 183 · al independiente se le carga con SUS costos (lo que le cobra el proveedor a él) */
    const mioC=(cI&&tipoDe(cI)==="independiente"&&cI.costos&&typeof cI.costos==="object")?cI.costos:{};
    (cps||[]).forEach(p=>{const cu=Number(mioC[p.id])>0?Number(mioC[p.id]):(Number(p.costo||0)>0?Number(p.costo):num(cc[p.cat],0,100000,0));snap[p.id]=cu;
      if(!cu)sinCosto.push(p.id);valorCosto+=cu*num(prods[p.id],0,9999);});
    valorCosto=Math.round(valorCosto*100)/100;
    detalle=Object.assign({},detalle,{costos:snap,valor_costo:valorCosto,sin_costo:sinCosto});
  }
  let{data:nc,error:eIns}=await db.from("cargas").insert({conductor:cond,items,prods,detalle,estado:"pendiente"}).select().single();
  let aviso="";
  if(eIns&&/prods/.test(eIns.message||"")){
    // la columna prods todavía no existe en la base: guardar sin el detalle y avisarlo
    const r2=await db.from("cargas").insert({conductor:cond,items,detalle,estado:"pendiente"}).select().single();
    nc=r2.data;eIns=r2.error;
    aviso="Falta ejecutar el SQL en Supabase (columna prods en cargas). La carga se guardó SIN el detalle por producto, así que el conductor no verá el stock producto por producto.";
  }
  if(eIns||!nc)return res.status(500).json({ok:false,error:"No se pudo guardar la carga: "+((eIns&&eIns.message)||"sin respuesta de la base")});
  // el viaje empieza aquí: se abre turno al conductor
  await db.from("conductores").update({en_turno:true,turno_hora:new Date().toISOString(),turno_ini:new Date().toISOString()}).eq("usuario",cond);
  await db.from("logs").insert({tipo:"turno",detalle:cond+" inicia (carga asignada)"});
  await avisoA(cond,"📦 Tienes una carga asignada: "+Object.keys(items).map(k=>k+" "+items[k]).join(", ")+". Confírmala antes de salir.");
  res.json({ok:true,id:nc.id,aviso:aviso||undefined,con_detalle:!!prods&&!aviso,valor_costo:valorCosto,sin_costo:sinCosto.length});
});
app.post("/admin/cargas/:id/reasignar",authA,async(req,res)=>{
  const cond=String(req.body.conductor||"").trim();
  if(!USR_RE.test(cond))return res.status(400).json({ok:false,error:"Conductor inválido"});
  await db.from("cargas").update({conductor:cond}).eq("id",req.params.id);
  await avisoA(cond,"📦 Se te reasignó una carga. Confírmala antes de salir.");
  await db.from("logs").insert({tipo:"admin",detalle:"Reasignó la carga #"+req.params.id+" a @"+cond});
  res.json({ok:true});
});
app.post("/admin/cargas/:id/cancelar",authA,async(req,res)=>{
  await db.from("cargas").update({estado:"cancelada"}).eq("id",req.params.id);
  await db.from("logs").insert({tipo:"admin",detalle:"Canceló la carga #"+req.params.id});
  res.json({ok:true});
});
app.get("/liquidaciones/sugerencia-prod",authA,async(req,res)=>{
  const u=String(req.query.conductor||"");
  if(!u)return res.json({ok:false,motivo:"sin_conductor"});
  // la carga anterior de ese conductor, tal cual fue
  const{data:cgs}=await db.from("cargas").select("prods,items,estado,creado").eq("conductor",u)
    .in("estado",["confirmada","con_diferencias","pendiente"]).order("id",{ascending:false}).limit(1);
  const ult=(cgs||[])[0];
  if(!ult)return res.json({ok:false,motivo:"sin_historial"});
  const prods=(ult.prods&&typeof ult.prods==="object")?ult.prods:null;
  if(!prods||!Object.keys(prods).length)return res.json({ok:false,motivo:"sin_detalle"});
  const limpio={};
  Object.keys(prods).forEach(id=>{const q=num(prods[id],0,99999);if(q>0)limpio[id]=q;});
  res.json({ok:true,prods:limpio,fecha:ult.creado||null,estado:ult.estado});
});
app.get("/liquidaciones/sugerencia",authA,async(req,res)=>{
  const u=String(req.query.conductor||"");
  // 1) historial de cargas realmente confirmadas por ese conductor
  const{data:cgs}=await db.from("cargas").select("items,items_final,estado,creado").eq("conductor",u)
    .in("estado",["confirmada","con_diferencias"]).order("id",{ascending:false}).limit(8);
  const viajes=(cgs||[]).map(c=>c.items_final||c.items||{});
  // 2) lo realmente VENDIDO por categoría en cada viaje (si las ventas traen cat)
  const{data:vts}=await db.from("ventas").select("items,creado").eq("conductor",u).order("creado",{ascending:false}).limit(1500);
  const vendCat={};let conCat=0;
  (vts||[]).forEach(v=>(Array.isArray(v.items)?v.items:[]).forEach(it=>{
    if(it&&it.cat&&CATS_OK.includes(it.cat)){vendCat[it.cat]=(vendCat[it.cat]||0)+num(it.c,0,9999);conCat++;}
  }));
  const nV=viajes.length;
  if(!nV)return res.json({ok:false,motivo:"sin_historial",viajes:0});
  const med=arr=>{const a=arr.slice().sort((x,y)=>x-y);const m=Math.floor(a.length/2);return a.length%2?a[m]:Math.round((a[m-1]+a[m])/2);};
  const items={},base={},tend={};
  CATS_OK.forEach(k=>{
    const serie=viajes.map(v=>num(v[k],0,99999));
    const b=med(serie); base[k]=b;
    if(nV>=3){
      const rec=med(serie.slice(0,Math.max(2,Math.round(nV/2))));   // mitad más reciente
      const ant=med(serie.slice(Math.max(2,Math.round(nV/2))));     // mitad anterior
      tend[k]=rec>ant*1.12?"sube":(rec<ant*0.88?"baja":"estable");
    } else tend[k]="pocos_datos";
    let sug=b;
    if(tend[k]==="sube")sug=Math.round(b*1.05);
    else if(tend[k]==="baja")sug=Math.round(b*0.95);
    items[k]=Math.max(0,sug);
  });
  res.json({ok:true,items,base,tendencia:tend,viajes:nV,
    confianza:nV>=5?"alta":(nV>=3?"media":"baja"),
    vendido_por_categoria:conCat?vendCat:null,
    nota:conCat?"Base = mediana de tus cargas confirmadas; la tendencia usa la mitad más reciente. Ya hay ventas con categoría: en los próximos viajes el cálculo usará lo vendido real."
      :"Base = mediana de tus cargas confirmadas (lo básico que suele llevar). Aún no hay ventas con categoría registrada: se afinará solo con el uso."});
});
app.post("/admin/tiendas/:id/editar",authA,async(req,res)=>{
  const{data:ant}=await db.from("tiendas").select("*").eq("id",req.params.id).maybeSingle();
  if(!ant)return res.status(404).json({ok:false,error:"Tienda no encontrada"});
  const campos={nombre:60,zona:40,tipo:20,dueno:60,tel:15,notas:200,hora_ini:5,hora_fin:5,ritmo:20};
  const upd={},cambios=[];
  /* Los días vienen marcados, no escritos: dias_no pasa a ser un texto que
     el servidor genera, nunca algo que el cliente mande. */
  if(req.body.dias!=null){
    const dn=diasNorm(req.body.dias);
    if(diasNorm(ant.dias_atiende)!==dn){
      upd.dias_atiende=dn; upd.dias_no=diasNoTexto(dn);
      cambios.push("Días: "+diasTexto(ant.dias_atiende)+" → "+diasTexto(dn));
    }
  }
  Object.keys(campos).forEach(k=>{
    if(req.body[k]==null)return;
    const v=(k==="tel")?String(req.body[k]).replace(/\D/g,"").slice(0,15):limpia(req.body[k],campos[k]);
    if(String(ant[k]||"")!==String(v||"")){upd[k]=v;cambios.push(k+': "'+(ant[k]||"—")+'" → "'+(v||"—")+'"');}
  });
  ["lat","lon"].forEach(k=>{ if(req.body[k]!=null){const v=num(req.body[k],k==="lat"?-90:-180,k==="lat"?90:180);
    if(Number(ant[k])!==v){upd[k]=v;cambios.push(k+": "+(ant[k]??"—")+" → "+v);} }});
  if(req.body.vip!=null&&!!ant.vip!==!!req.body.vip){upd.vip=!!req.body.vip;cambios.push("VIP: "+(req.body.vip?"sí":"no"));}
  if(req.body.act!=null&&!!ant.act!==!!req.body.act){upd.act=!!req.body.act;cambios.push("Activa: "+(req.body.act?"sí":"no"));}
  if((upd.lat!==undefined||upd.lon!==undefined)&&!ant.lug_manual){   /* 181 · se movió: vuelve a calcular su distrito */
    const ub=ubicarGPS(upd.lat!==undefined?upd.lat:ant.lat,upd.lon!==undefined?upd.lon:ant.lon);
    if(ub!==ant.ubigeo){upd.ubigeo=ub;cambios.push("Lugar: "+(nombreLugar(ant.ubigeo)||"—")+" → "+(nombreLugar(ub)||"sin ubicar"));}
  }
  if(!cambios.length)return res.json({ok:true,sin_cambios:true});
  await db.from("tiendas").update(upd).eq("id",req.params.id);
  await db.from("logs").insert({tipo:"tienda",detalle:"#"+req.params.id+" "+(ant.nombre||"")+" · "+cambios.join(" · ")});
  res.json({ok:true,cambios:cambios.length});
});
/* 182 · deudas de una tienda, por acreedor y deuda por deuda (PEPS) */
app.get("/admin/tiendas/:id/deudas",authA,async(req,res)=>{
  const[cs,N]=await Promise.all([deudasDetalle(Number(req.params.id)),nombresAcreedores()]);
  res.set("Cache-Control","no-store").json({ok:true,cuentas:cs.map(c=>Object.assign({nombre:N[c.acreedor]||c.acreedor},c))});
});
app.get("/conductor/tiendas/:id/deudas",authC,async(req,res)=>{
  const{data:t}=await db.from("tiendas").select("*").eq("id",req.params.id).maybeSingle();
  const{data:yo}=await db.from("conductores").select("usuario,tipo,lugares").eq("usuario",req.cond.u).maybeSingle();
  if(!t||!yo||!puedeVer(yo,t,await getParams()))return res.status(403).json({ok:false,error:"Esa tienda no está habilitada para ti"});
  const[cs,N]=await Promise.all([deudasDetalle(t.id),nombresAcreedores()]);
  res.set("Cache-Control","no-store").json({ok:true,mi_cuenta:tipoDe(yo)==="independiente"?yo.usuario:"dueno",cuentas:cs.map(c=>Object.assign({nombre:N[c.acreedor]||c.acreedor},c))});
});
app.get("/admin/tiendas/:id/historial",authA,async(req,res)=>{
  const{data}=await db.from("logs").select("*").eq("tipo","tienda").ilike("detalle","#"+req.params.id+" %").order("id",{ascending:false}).limit(40);
  res.json({ok:true,filas:data||[]});
});
app.post("/tiendas/:id/verificar",authA,async(req,res)=>{
  try{await db.from("eventos").update({visto:true}).eq("tipo","tienda_nueva").eq("ref",String(req.params.id));}catch(e){}await db.from("tiendas").update({verificada:true,nueva:false}).eq("id",req.params.id);res.json({ok:true});});
app.post("/tiendas/:id/credito",authA,async(req,res)=>{const{data:_tc}=await db.from("tiendas").select("ubigeo").eq("id",req.params.id).maybeSingle();await db.from("tiendas").update({cr:!!req.body.habilitado,li:num(req.body.limite,0,100000)||limiteLugar(await getParams(),_tc&&_tc.ubigeo)}).eq("id",req.params.id);
  await db.from("logs").insert({tipo:"admin",detalle:"Crédito tienda #"+req.params.id+" → S/"+num(req.body.limite,0,100000)});res.json({ok:true});});
app.post("/admin/tiendas",authA,async(req,res)=>{
  const b=req.body;
  if(!b.n)return res.status(400).json({ok:false,error:"Falta el nombre"});
  const _pmsN=await getParams();
  const _diasN=diasNorm(b.dias);
  const fila={nombre:b.n,zona:b.z||"",tipo:b.tp||"bodega",ritmo:ritmoDe(_pmsN,b.ritmo).id,
    dias_atiende:_diasN,dueno:b.d||"",tel:String(b.tel||"").replace(/\D/g,"").slice(0,15),notas:b.no||"",hora_ini:limpia(b.h_ini,5),hora_fin:limpia(b.h_fin,5),dias_no:diasNoTexto(_diasN),lat:(b.lat==null?null:num(b.lat,-90,90)),lon:(b.lon==null?null:num(b.lon,-180,180)),cr:!!b.cr,sa:0,li:Number(b.li)||(b.cr?limiteLugar(_pmsN,(b.lat!=null&&b.lon!=null)?ubicarGPS(b.lat,b.lon):null):0),vip:false,act:true,nueva:false,verificada:true,conductor_reg:"admin",ubigeo:(b.lat!=null&&b.lon!=null)?ubicarGPS(b.lat,b.lon):null};
  if(b.conductor){fila.conductor_asig=b.conductor;fila.asig_fecha=hoy();} // reservada: no vence
  const{data:t,error}=await db.from("tiendas").insert(fila).select().single();
  if(error)return res.status(500).json({ok:false,error:error.message});
  if(b.conductor)await avisoA(b.conductor,"🏪 Te asigné la tienda "+b.n+(b.z?" ("+b.z+")":"")+" — entra en tu ruta de HOY.");
  res.json({ok:true,id:t.id});
});
app.post("/admin/tiendas/ritmo",authA,async(req,res)=>{
  /* Clasificar 100 tiendas una por una no es viable: esto asigna el ritmo a
     toda una zona, o a una lista de tiendas, de una sola vez. */
  const _p=await getParams(), R=ritmoDe(_p,req.body.ritmo);
  if(!req.body.ritmo||R.id!==String(req.body.ritmo))
    return res.status(400).json({ok:false,error:"Ese ritmo no existe en Configuración"});
  let q=db.from("tiendas").update({ritmo:R.id});
  if(Array.isArray(req.body.ids)&&req.body.ids.length){
    q=q.in("id",req.body.ids.slice(0,500).map(x=>Number(x)||0).filter(Boolean));
  }else if(req.body.zona){
    q=q.eq("zona",limpia(req.body.zona,40));
  }else return res.status(400).json({ok:false,error:"Indica una zona o una lista de tiendas"});
  const{data,error}=await q.select("id");
  if(error)return res.status(500).json({ok:false,error:error.message});
  const n=(data||[]).length;
  await db.from("logs").insert({tipo:"tienda",detalle:"Ritmo → "+R.nombre+" en "+n+" tienda(s)"+(req.body.zona?" de la zona "+req.body.zona:"")});
  res.json({ok:true,cambiadas:n,ritmo:R.id});
});
app.post("/admin/tiendas/:id/asignar",authA,async(req,res)=>{
  const{data:t}=await db.from("tiendas").select("nombre,zona").eq("id",req.params.id).maybeSingle();
  if(!t)return res.status(404).json({ok:false});
  await db.from("tiendas").update({conductor_asig:req.body.conductor||null,asig_fecha:req.body.conductor?hoy():null}).eq("id",req.params.id); // reservada hasta que el dueño la cambie
  if(req.body.conductor)await avisoA(req.body.conductor,"🏪 Te asigné la tienda "+t.nombre+(t.zona?" ("+t.zona+")":"")+" — entra en tu ruta de HOY.");
  res.json({ok:true});
});
/* 175 · se quitó POST /creditos: duplicaba /admin/creditos/abono y ninguna app lo usaba */
app.post("/correcciones/:id/resolver",authA,async(req,res)=>{
  const{data:c}=await db.from("correcciones").select("*").eq("id",req.params.id).maybeSingle();
  if(!c)return res.status(404).json({ok:false});
  await db.from("correcciones").update({estado:req.body.aprobada?"aprobada":"rechazada"}).eq("id",c.id);
  await db.from("kardex").insert({conductor:c.conductor,tipo:"correccion",detalle:c.referencia+" → S/"+c.monto_correcto+" ("+(req.body.aprobada?"APROBADA":"rechazada")+") — "+c.motivo});
  await avisoA(c.conductor,(req.body.aprobada?"✓ Aprobada":"✗ Rechazada")+" tu corrección de "+c.tienda+" ("+c.referencia+" → S/"+c.monto_correcto+").");
  res.json({ok:true});
});
app.post("/eventos/:id/visto",authA,async(req,res)=>{await db.from("eventos").update({visto:true}).eq("id",req.params.id);res.json({ok:true});});
app.get("/admin/categorias",authA,async(req,res)=>{
  const{data}=await db.from("categorias").select("*").order("orden");
  res.json({ok:true,categorias:data||[]});
});
app.post("/admin/categorias",authA,async(req,res)=>{
  const arr=Array.isArray(req.body.categorias)?req.body.categorias.slice(0,40):[];
  /* 175 · Configuración → precio por defecto de una categoría nueva */
  const _pc=await getParams(),PN=num(_pc.catalogo_cfg&&_pc.catalogo_cfg.precio_cat_nueva,0,10000,0);
  if(PN>0){const{data:exis}=await db.from("categorias").select("id");const ya=new Set((exis||[]).map(c=>c.id));
    arr.forEach(x=>{const id=limpia(x&&x.id,20).toLowerCase().replace(/[^a-z0-9_]/g,"");if(x&&id&&!ya.has(id)&&!(Number(x.precio)>0))x.precio=PN;});}
  const filas=arr.map((x,i)=>({id:limpia(x.id,20).toLowerCase().replace(/[^a-z0-9_]/g,""),nom:limpia(x.nom,50),
    emoji:limpia(x.emoji,4)||"📦",precio:num(x.precio,0,10000),orden:i,activa:x.activa!==false})).filter(x=>x.id&&x.nom);
  if(!filas.length)return res.status(400).json({ok:false,error:"Sin categorías"});
  const{error}=await db.from("categorias").upsert(filas);
  await refrescarCats();
  // el panel manda la lista completa: lo que no está en ella se desactiva.
  // Antes, borrar una categoría en el panel no la desactivaba aquí y seguía
  // llegándole al conductor.
  if(!error&&req.body.exclusivo===true){
    const vivos=filas.map(f=>f.id);
    await db.from("categorias").update({activa:false}).not("id","in","("+vivos.map(v=>'"'+v+'"').join(",")+")");
  }
  if(error)return res.status(500).json({ok:false,error:error.message});
  res.json({ok:true,guardadas:filas.length});
});
app.post("/admin/categorias/:id/borrar",authA,async(req,res)=>{
  await db.from("categorias").update({activa:false}).eq("id",req.params.id);
  await db.from("logs").insert({tipo:"admin",detalle:"Desactivó categoría: "+req.params.id});
  res.json({ok:true});
});
/* 178 · Costo de compra (lo que te cobra el proveedor), producto por producto o toda
   una categoría de un golpe, desde la pantalla de carga. */
app.post("/admin/catalogo/costos",authA,async(req,res)=>{
  const c=(req.body.costos&&typeof req.body.costos==="object")?req.body.costos:{};
  const ids=Object.keys(c).slice(0,300).map(k=>limpia(k,40)).filter(Boolean);
  const cat=req.body.categoria&&typeof req.body.categoria==="object"?req.body.categoria:null;
  if(!ids.length&&!cat)return res.status(400).json({ok:false,error:"No hay costos para guardar"});
  let n=0;const fallas=[];
  if(ids.length){
    const{data:ex}=await db.from("catalogo").select("id").in("id",ids);
    const hay=new Set((ex||[]).map(p=>p.id));
    for(const id of ids){
      if(!hay.has(id)){fallas.push(id);continue;}
      const{error}=await db.from("catalogo").update({costo:num(c[id],0,100000,0)}).eq("id",id);
      if(error)fallas.push(id);else n++;
    }
  }
  if(cat&&cat.id){
    const kv=await getParams();kv.costos=kv.costos||{};
    kv.costos[limpia(cat.id,30)]=num(cat.costo,0,100000,0);
    const{error:eP}=await db.from("params").upsert({id:1,kv});
    if(eP)return res.status(500).json({ok:false,error:"No se pudo guardar el costo de la categoría: "+eP.message});
  }
  res.json({ok:!fallas.length,actualizados:n,error:fallas.length?("No se pudo guardar el costo de: "+fallas.join(", ")):undefined});
});
app.post("/admin/catalogo/producto",authA,async(req,res)=>{
  const p=req.body||{};
  let id=limpia(p.id,20).toLowerCase().replace(/[^a-z0-9_]/g,"");
  if(!id||!p.cat||!p.nombre)return res.status(400).json({ok:false,error:"Faltan datos"});
  const nombre=limpia(p.nombre,60),cat=limpia(p.cat,20);
  // el identificador se recorta a 20 caracteres: dos nombres largos parecidos
  // podían acabar con el mismo y pisarse. Se busca uno libre.
  const{data:ya}=await db.from("catalogo").select("id,nombre,cat").eq("id",id).maybeSingle();
  if(ya&&(ya.nombre!==nombre||ya.cat!==cat)){
    let base=id.slice(0,18),n=2,libre=null;
    while(n<50){
      const cand=base+"_"+n;
      const{data:ex}=await db.from("catalogo").select("id").eq("id",cand).maybeSingle();
      if(!ex){libre=cand;break;}
      n++;
    }
    if(!libre)return res.status(409).json({ok:false,error:"No se pudo crear: demasiados productos con nombre parecido"});
    id=libre;
  }
  const precios={};
  if(p.precios&&typeof p.precios==="object")
    Object.keys(p.precios).slice(0,12).forEach(k=>{const v=num(p.precios[k],0,10000);if(v)precios[limpia(k,20)]=v;});
  const{error}=await db.from("catalogo").upsert({id,cat,nombre,
    precio:num(p.precio,0,10000),costo:num(p.costo,0,10000),precios,activo:p.activo!==false});
  if(error)return res.status(500).json({ok:false,error:error.message});
  res.json({ok:true,id});
});
app.post("/admin/catalogo/:id/tipo",authA,async(req,res)=>{
  const tipo=limpia(req.body.tipo,20),activo=req.body.activo!==false;
  if(!tipo)return res.status(400).json({ok:false,error:"Falta el tipo de tienda"});
  const{data:p,error:e1}=await db.from("catalogo").select("no_tipos,nombre").eq("id",req.params.id).maybeSingle();
  if(e1||!p)return res.status(404).json({ok:false,error:"Producto no encontrado"});
  let lista=Array.isArray(p.no_tipos)?p.no_tipos.slice():[];
  lista=lista.filter(x=>x!==tipo);
  if(!activo)lista.push(tipo);
  const{error:e2}=await db.from("catalogo").update({no_tipos:lista}).eq("id",req.params.id);
  if(e2)return res.status(500).json({ok:false,error:/no_tipos/.test(e2.message||"")
    ?"Falta ejecutar el SQL en Supabase (columna no_tipos en catalogo)":e2.message});
  await db.from("logs").insert({tipo:"admin",detalle:(activo?"Devolvió":"Quitó")+" "+(p.nombre||req.params.id)+" para tipo "+tipo});
  res.json({ok:true,no_tipos:lista});
});
app.post("/admin/catalogo/:id/borrar",authA,async(req,res)=>{
  await db.from("catalogo").update({activo:false}).eq("id",req.params.id);
  await db.from("logs").insert({tipo:"admin",detalle:"Quitó del catálogo: "+req.params.id});
  res.json({ok:true});
});
app.get("/admin/utilidad",authA,async(req,res)=>{
  const d=String(req.query.desde||"").slice(0,10)||hoy();
  const h=String(req.query.hasta||"").slice(0,10)||hoy();
  const cond=limpia(req.query.conductor,20);
  let qv=db.from("ventas").select("items,total,creado,conductor,costo,anulada").gte("creado",iniDia(d)).lte("creado",finDia(h));
  if(cond&&cond!=="todos")qv=qv.eq("conductor",cond);
  const IND=await independientes();   /* 183 · sin independientes; con el costo PEPS de cada venta */
  const [vts0,prods,params]=await Promise.all([
    qv,
    db.from("catalogo").select("id,cat,nombre,costo"),
    getParams()
  ]).then(r=>[r[0].data||[],r[1].data||[],r[2]]);
  const vts=vts0.filter(v=>!v.anulada&&(IND.has(cond)||!IND.has(v.conductor)));
  const costoProd={},catDe={},nomDe={};
  prods.forEach(p=>{costoProd[p.id]=Number(p.costo||0);catDe[p.id]=p.cat;nomDe[p.id]=p.nombre;});
  const costoCat=params.costos||{};
  let venta=0,costo=0,sinCosto=0;
  const porCat={};
  vts.forEach(v=>{
    const its=(Array.isArray(v.items)?v.items:[]).filter(it=>it&&it.id);
    /* si la venta trae su costo PEPS, se reparte entre sus productos según el costo de referencia */
    const refV=its.reduce((a,it)=>{const c0=costoProd[it.id]>0?costoProd[it.id]:num(costoCat[catDe[it.id]||"—"],0,10000);return a+num(it.c,0,9999)*c0;},0);
    const fac=(v.costo!=null&&Number(v.costo)>=0&&refV>0)?Number(v.costo)/refV:1;
    its.forEach(it=>{
      const q=num(it.c,0,9999),pu=num(it.pu,0,10000);
      const cat=catDe[it.id]||"—";
      const cu=(costoProd[it.id]>0?costoProd[it.id]:num(costoCat[cat],0,10000))*fac;
      if(!cu)sinCosto+=q;
      venta+=q*pu;costo+=q*cu;
      const r0=porCat[cat]||(porCat[cat]={venta:0,costo:0,unid:0});
      r0.venta+=q*pu;r0.costo+=q*cu;r0.unid+=q;
    });
  });
  res.json({ok:true,desde:d,hasta:h,venta,costo,utilidad:venta-costo,
    margen:venta>0?Math.round((venta-costo)/venta*1000)/10:0,
    unidades_sin_costo:sinCosto,
    por_categoria:Object.keys(porCat).map(k=>({cat:k,...porCat[k],utilidad:porCat[k].venta-porCat[k].costo}))
      .sort((a,b)=>b.utilidad-a.utilidad)});
});
app.get("/admin/catalogo",authA,async(req,res)=>{
  const{data}=await db.from("catalogo").select("*").order("cat");
  res.json({ok:true,productos:data||[]});
});
app.post("/admin/catalogo",authA,async(req,res)=>{
  const arr=Array.isArray(req.body.productos)?req.body.productos.slice(0,400):[];
  if(!arr.length)return res.status(400).json({ok:false,error:"Sin productos"});
  // precios que YA existen, para no borrar los de otros tipos de tienda
  const ids=arr.map(p=>limpia(p.id,20)).filter(Boolean);
  const{data:previos}=await db.from("catalogo").select("id,precios").in("id",ids);
  const antes={};(previos||[]).forEach(p=>{antes[p.id]=(p.precios&&typeof p.precios==="object")?p.precios:{}});
  const filas=arr.map(p=>{
    const id=limpia(p.id,20);
    const nuevos={};
    Object.keys(p.precios||{}).slice(0,12).forEach(k=>{const v=num(p.precios[k],0,10000);if(v)nuevos[limpia(k,20)]=v;});
    // se mezclan: lo que llega manda sobre su tipo, lo demás se conserva
    // si el panel manda la lista completa de ese producto, se respeta tal cual
    // (así puede QUITAR el precio de un tipo); si no, se mezcla con lo guardado
    const precios=(p.reemplazar_precios===true)?nuevos:Object.assign({},antes[id]||{},nuevos);
    return{id,cat:limpia(p.cat,20),nombre:limpia(p.nombre,60),
      precio:num(p.precio,0,10000),costo:num(p.costo,0,10000),precios};
  }).filter(p=>p.id);
  await db.from("logs").insert({tipo:"admin",detalle:"Editó precios/costos de "+filas.length+" producto(s)"});
  const{error}=await db.from("catalogo").upsert(filas);
  if(error)return res.status(500).json({ok:false,error:error.message});
  res.json({ok:true,guardados:filas.length});
});
app.get("/admin/respaldo",authA,async(req,res)=>{
  // Copia completa del sistema en un solo archivo JSON
  const tablas=["conductores","tiendas","ventas","creditos_mov","visitas","pedidos","avisos","cargas",
    "traspasos","correcciones","eventos","liquidaciones","kardex","categorias","catalogo","params","boletas","posiciones"];
  const out={version:"5.0",fecha:new Date().toISOString(),tablas:{}};
  for(const t of tablas){
    try{
      const lim=(t==="posiciones")?5000:20000;
      const{data}=await db.from(t).select("*").limit(lim);
      if(t==="conductores")out.tablas[t]=(data||[]).map(x=>{const y={...x};delete y.pass_hash;return y;}); // sin contraseñas
      else out.tablas[t]=data||[];
    }catch(e){out.tablas[t]="error: "+e.message;}
  }
  out.resumen=Object.fromEntries(Object.entries(out.tablas).map(([k,v])=>[k,Array.isArray(v)?v.length:0]));
  await db.from("params").upsert({id:2,kv:{ultimo_respaldo:new Date().toISOString()}});
  res.setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Content-Disposition",`attachment; filename="respaldo-${hoy()}.json"`);
  res.send(JSON.stringify(out,null,1));
});
app.get("/admin/auditoria",authA,async(req,res)=>{
  const{data}=await db.from("logs").select("*").eq("tipo","admin").order("id",{ascending:false}).limit(200);
  res.json({ok:true,filas:data||[]});
});
app.get("/admin/exportar",authA,async(req,res)=>{
  const tipo=String(req.query.tipo||"ventas"), cond=String(req.query.conductor||""), desde=String(req.query.desde||""), hasta=String(req.query.hasta||"");
  const csv=(cab,filas)=>[cab.join(";")].concat(filas.map(f=>f.map(v=>{
    const s=String(v==null?"":v).replace(/"/g,'""');return /[;\n"]/.test(s)?'"'+s+'"':s;}).join(";"))).join("\n");
  const rango=q=>{if(desde)q=q.gte("creado",iniDia(desde));if(hasta)q=q.lte("creado",finDia(hasta));return q;};
  let cab=[],filas=[],nombre=tipo;
  try{
    if(tipo==="ventas"){
      let q=db.from("ventas").select("*").order("creado",{ascending:false}).limit(5000);
      if(cond)q=q.eq("conductor",cond); const{data}=await rango(q);
      cab=["Fecha","Hora","Tienda","Conductor","Productos","Metodo","Efectivo S/","Fiado S/","Abono S/","Total S/"];
      filas=(data||[]).map(v=>{const d=new Date(v.creado);return [d.toLocaleDateString("es-PE"),d.toLocaleTimeString("es-PE",{hour:"2-digit",minute:"2-digit"}),v.tienda,v.conductor,v.resumen||"",v.metodo,Number(v.efectivo||0).toFixed(2),Number(v.credito||0).toFixed(2),Number(v.abono||0).toFixed(2),Number(v.total||0).toFixed(2)];});
    }else if(tipo==="deudas"){
      const{data}=await db.from("tiendas").select("nombre,zona,dueno,tel,sa,li,cr").gt("sa",0).order("sa",{ascending:false});
      cab=["Tienda","Zona","Dueño","Teléfono","Deuda S/","Límite S/","Al tope"];
      filas=(data||[]).map(t=>[t.nombre,t.zona||"",t.dueno||"",t.tel||"",Number(t.sa||0).toFixed(2),Number(t.li||0).toFixed(2),Number(t.sa)>=Number(t.li||230)?"SI":"no"]);
    }else if(tipo==="gastos"){
      let q=db.from("kardex").select("*").like("tipo","gasto_%").order("creado",{ascending:false}).limit(3000);
      if(cond)q=q.eq("conductor",cond); const{data}=await rango(q);
      cab=["Fecha","Conductor","Categoría","Detalle"];
      filas=(data||[]).map(k=>[new Date(k.creado).toLocaleDateString("es-PE"),k.conductor,String(k.tipo).replace("gasto_",""),k.detalle||""]);
    }else if(tipo==="creditos"){
      let q=db.from("creditos_mov").select("*").order("creado",{ascending:false}).limit(4000); const{data}=await rango(q);
      const{data:tds}=await db.from("tiendas").select("id,nombre");
      const map={};(tds||[]).forEach(t=>map[t.id]=t.nombre);
      cab=["Fecha","Tienda","Tipo","Monto S/","Detalle","Registrado por"];
      filas=(data||[]).map(m=>[new Date(m.creado).toLocaleDateString("es-PE"),map[m.tienda_id]||m.tienda_id,m.tipo,Number(m.monto||0).toFixed(2),m.detalle||"",m.por||""]);
    }else if(tipo==="tiendas"){
      const{data}=await db.from("tiendas").select("*").order("nombre");
      cab=["Tienda","Zona","Tipo","Dueño","Teléfono","Horario","Deuda S/","VIP","Asignada a","Activa"];
      filas=(data||[]).map(t=>[t.nombre,t.zona||"",t.tipo||"",t.dueno||"",t.tel||"",(t.hora_ini||"")+(t.hora_fin?" a "+t.hora_fin:""),Number(t.sa||0).toFixed(2),t.vip?"SI":"no",t.conductor_asig||"",t.act?"SI":"no"]);
    }else if(tipo==="liquidaciones"){
      let q=db.from("liquidaciones").select("*").order("creado",{ascending:false}).limit(1000);
      if(cond)q=q.eq("conductor",cond); const{data}=await rango(q);
      cab=["Fecha","Conductor","Efectivo S/","Yape S/","Abonos S/","Entregas S/"];
      filas=(data||[]).map(l=>[new Date(l.creado).toLocaleDateString("es-PE"),l.conductor,Number(l.dia?.vEf||0).toFixed(2),Number(l.dia?.vYape||0).toFixed(2),Number(l.dia?.abonos||0).toFixed(2),Number(l.dia?.entregas||0).toFixed(2)]);
    }else return res.status(400).json({ok:false,error:"Tipo no válido"});
    const texto="\ufeff"+csv(cab,filas);
    res.setHeader("Content-Type","text/csv; charset=utf-8");
    res.setHeader("Content-Disposition",`attachment; filename="${nombre}-${hoy()}.csv"`);
    res.send(texto);
  }catch(e){res.status(500).json({ok:false,error:e.message});}
});
app.get("/admin/gps/probar",authA,async(req,res)=>{
  const pos=await obtenerGPS();
  const{data:cs}=await db.from("conductores").select("usuario,nombre,gps_id");
  res.json({ok:true,plataforma:GPS_PLAT||"(ninguna)",url:process.env.GPS_API_URL||"(vacía)",
    vehiculos:pos.length,error:GPS_ULTIMO_ERROR||null,
    ids_plataforma:pos.slice(0,20).map(p=>p.gps_id),
    conductores:(cs||[]).map(c=>({usuario:c.usuario,nombre:c.nombre,gps_id:c.gps_id||null,
      coincide:!!(c.gps_id&&pos.some(p=>p.gps_id===String(c.gps_id)))}))});
});
app.get("/admin/diagnostico",authA,async(req,res)=>{
  const out={};
  for(const t of ["conductores","tiendas","ventas","pedidos","cargas","visitas","kardex","posiciones","eventos","catalogo","categorias"]){
    try{const{count}=await db.from(t).select("*",{count:"exact",head:true});out[t]=count??0;}catch(e){out[t]="error: "+e.message;}
  }
  const{data:ult}=await db.from("tiendas").select("id,nombre,zona,lat,lon,nueva,verificada,conductor_reg,conductor_asig,creado").order("id",{ascending:false}).limit(10);
  const{data:pds}=await db.from("pedidos").select("id,tienda,tienda_id,conductor,fecha,estado").order("id",{ascending:false}).limit(10);
  const{data:cgs}=await db.from("cargas").select("id,conductor,estado,items,detalle,creado").order("id",{ascending:false}).limit(20);
  /* 178 · cada carga con su valor al costo (sin mandar todo el detalle) */
  const cgv=(cgs||[]).map(c=>{const d=c.detalle||{};const x=Object.assign({},c);delete x.detalle;
    if(d.valor_costo!=null){x.valor_costo=d.valor_costo;x.sin_costo=(d.sin_costo||[]).length;}return x;});
  res.json({ok:true,conteos:out,ultimas_tiendas:ult||[],ultimos_pedidos:pds||[],ultimas_cargas:cgv,gps_error:GPS_ULTIMO_ERROR||null});
});
/* 175 · El conductor deja mercadería en el almacén: pasa de SU stock al del almacén,
   producto por producto. Antes: la pantalla "Depositar al almacén" no mandaba nada, y
   este envío (por categoría) solo anotaba un contador aparte que no era el stock real. */
app.post("/almacen",authC,async(req,res)=>{
  if((await independientes()).has(req.cond.u))return res.status(403).json({ok:false,error:"Un independiente le vende al almacén por traspaso, no lo deja gratis."});   /* 183 */
  const prods=limpiaProds(req.body.prods);
  if(!Object.keys(prods).length)return res.status(400).json({ok:false,error:"Elige los productos que dejas (esta versión de la app es antigua: actualízala)"});
  const st=await leerStock(req.cond.u);
  const falta=Object.keys(prods).filter(id=>Number(st.prods[id]||0)<prods[id]);
  if(falta.length){
    const{data:cat}=await db.from("catalogo").select("id,nombre").in("id",falta);
    const nom={};(cat||[]).forEach(p=>nom[p.id]=p.nombre);
    return res.status(409).json({ok:false,error:"No tienes tanto en el camión: "+falta.map(id=>(nom[id]||id)+" (tienes "+Number(st.prods[id]||0)+")").join(", ")});
  }
  const salA=await moverStock(req.cond.u,Object.fromEntries(Object.keys(prods).map(id=>[id,-prods[id]])),"traspaso_envia","almacen");
  await moverStock("almacen",prods,"traspaso_recibe",req.cond.u,{capas:salA.capas});   /* 183 */
  const cats=await porCategoria(prods);
  const det=Object.keys(cats).map(k=>k+" "+cats[k]).join(", ");
  await db.from("kardex").insert({conductor:req.cond.u,tipo:"almacen_retorno",detalle:JSON.stringify(cats)+" · dejado por "+req.cond.u+(req.body.nota?" · "+limpia(req.body.nota,120):"")});
  await evento("almacen","🏬 "+req.cond.u+" dejó mercadería en el almacén",det+". Ya pasó al stock del almacén; si no coincide con lo que recibiste, corrígelo en Almacén → Ajuste.","");
  res.json({ok:true,por_categoria:cats});
});
app.post("/admin/almacen/enviar",authA,async(req,res)=>{
  const para=String(req.body.conductor||"");
  const prodsA=limpiaProds(req.body.prods||req.body.items);
  if(!Object.keys(prodsA).length||!USR_RE.test(para))return res.status(400).json({ok:false,error:"Faltan datos"});
  if((await independientes()).has(para))return res.status(400).json({ok:false,error:"Es independiente: véndele desde Traspasos, con precio y forma de pago"});   /* 185 */
  const items=await porCategoria(prodsA);
  const{data:t}=await db.from("traspasos").insert({de:"almacen",de_nombre:"Almacén",para,prods:prodsA,items,conf_de:true,estado:"parcial"}).select().single();
  await avisoA(para,"🏬 El almacén te envía: "+Object.keys(items).map(k=>k+" "+items[k]).join(", ")+". Confírmalo al recibirlo.");
  res.json({ok:true,id:t.id});
});
app.post("/admin/almacen/pedir",authA,async(req,res)=>{
  const de=String(req.body.conductor||"");
  const prodsR=limpiaProds(req.body.prods||req.body.items);
  if(!Object.keys(prodsR).length||!USR_RE.test(de))return res.status(400).json({ok:false,error:"Faltan datos"});
  if((await independientes()).has(de))return res.status(400).json({ok:false,error:"Es independiente: cómprale desde Traspasos, con precio y forma de pago"});   /* 185 */
  const items=await porCategoria(prodsR);
  const{data:t}=await db.from("traspasos").insert({de,de_nombre:de,para:"almacen",prods:prodsR,items,conf_para:true,estado:"parcial"}).select().single();
  await avisoA(de,"🏬 Debes entregar al almacén: "+Object.keys(items).map(k=>k+" "+items[k]).join(", ")+". Confirma cuando lo dejes.");
  res.json({ok:true,id:t.id});
});
app.get("/admin/creditos",authA,async(req,res)=>{
  const{data:mov0}=await db.from("creditos_mov").select("*").order("id",{ascending:false}).limit(400);
  const mov=(mov0||[]).filter(m=>acreedorDe(m)==="dueno").slice(0,200);   /* 182 · solo tu cuenta */
  const{data:tds}=await db.from("tiendas").select("id,nombre,sa,li,cr");
  const map={};(tds||[]).forEach(t=>map[t.id]=t.nombre);
  res.json({ok:true,
    movimientos:(mov||[]).map(m=>({...m,tienda:map[m.tienda_id]||("#"+m.tienda_id)})),
    saldos:await (async()=>{
      /* 175 · antigüedad de cada deuda: días desde el cargo más antiguo que aún no se cubrió */
      const p=await getParams();const DV=num((p.credito_cfg&&p.credito_cfg.dias_vencida)||p.deuda_dias,1,365,30);
      const cons=(tds||[]).filter(t=>Number(t.sa||0)>0).sort((a,b)=>Number(b.sa)-Number(a.sa));
      for(const t of cons){
        const{data:ms0}=await db.from("creditos_mov").select("tipo,monto,creado,acreedor").eq("tienda_id",t.id).order("creado",{ascending:true});
        const ms=(ms0||[]).filter(m=>acreedorDe(m)==="dueno");
        let pag=(ms||[]).filter(m=>m.tipo!=="cargo").reduce((s,m)=>s+Number(m.monto||0),0),desde=null;
        for(const m of (ms||[]).filter(m=>m.tipo==="cargo")){if(pag>=Number(m.monto||0)){pag-=Number(m.monto||0);continue;}desde=m.creado;break;}
        t.dias=desde?Math.floor((Date.now()-new Date(desde).getTime())/86400000):0;
        t.vencida=t.dias>=DV;t.dias_vencida=DV;
      }
      return cons;})(),
    total:(tds||[]).reduce((s,t)=>s+Number(t.sa||0),0)});
});
app.post("/admin/creditos/abono",authA,async(req,res)=>{
  const id=req.body.tienda_id, monto=num(req.body.monto,0.1,999999);
  if(!id||!monto)return res.status(400).json({ok:false,error:"Falta tienda o monto"});
  const{data:t}=await db.from("tiendas").select("nombre,sa").eq("id",id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Tienda no encontrada"});
  const r=await moverDeuda(id,"abono",monto,limpia(req.body.detalle,120)||"Abono registrado por el dueño","admin");
  if(!r.monto)return res.status(409).json({ok:false,error:"Esa tienda no tiene deuda que abonar"});
  await db.from("logs").insert({tipo:"admin",detalle:"Abono S/"+r.monto.toFixed(2)+" de "+t.nombre});
  res.json({ok:true,nuevo_saldo:r.sa,registrado:r.monto,
    aviso:(r.monto<monto)?("Solo debía S/"+r.monto.toFixed(2)+": se registró eso."):undefined});
});
/* 175 · El almacén se lee del stock real por producto (antes: suma de los últimos 300
   movimientos por categoría, un inventario aparte que no coincidía con los envíos) */
app.get("/admin/almacen",authA,async(req,res)=>{
  res.set("Cache-Control","no-store");
  const s=await leerStock("almacen");
  const{data:cat}=await db.from("catalogo").select("id,nombre,cat");
  const nom={},cDe={};(cat||[]).forEach(p=>{nom[p.id]=p.nombre;cDe[p.id]=p.cat});
  const prods=Object.keys(s.prods).filter(id=>Number(s.prods[id])>0).map(id=>({id,n:nom[id]||id,cat:cDe[id]||"—",cant:Number(s.prods[id])}));
  const stock={};prods.forEach(p=>{stock[p.cat]=(stock[p.cat]||0)+p.cant});
  const{data:mv}=await db.from("stock_mov").select("prod_id,delta,motivo,ref,creado").eq("conductor","almacen").order("creado",{ascending:false}).limit(80);
  const MOT={traspaso_recibe:"Recibido",traspaso_envia:"Enviado",ajuste_ingreso:"Ajuste: ingreso",ajuste_salida:"Ajuste: salida",cierre_recibe:"Cierre de viaje"};
  res.json({ok:true,stock,prods,total:prods.reduce((a,p)=>a+p.cant,0),
    movimientos:(mv||[]).map(m=>({prod:nom[m.prod_id]||m.prod_id,cant:Number(m.delta),motivo:MOT[m.motivo]||m.motivo,de:m.ref||"",creado:m.creado}))});
});
app.post("/admin/almacen/ajuste",authA,async(req,res)=>{
  const prods=limpiaProds(req.body.prods);
  if(!Object.keys(prods).length)return res.status(400).json({ok:false,error:"Elige los productos y cantidades del ajuste"});
  const tipo=(req.body.tipo==="salida")?"salida":"ingreso";
  if(tipo==="salida"){
    const st=await leerStock("almacen");
    const falta=Object.keys(prods).filter(id=>Number(st.prods[id]||0)<prods[id]);
    if(falta.length)return res.status(409).json({ok:false,error:"El almacén no tiene tanto de: "+falta.join(", ")});
  }
  const nota=limpia(req.body.nota,120);
  await moverStock("almacen",Object.fromEntries(Object.keys(prods).map(id=>[id,(tipo==="salida"?-1:1)*prods[id]])),"ajuste_"+tipo,nota||"dueño");
  const cats=await porCategoria(prods);
  await db.from("kardex").insert({conductor:"admin",tipo:tipo==="salida"?"almacen_salida":"almacen_retorno",detalle:JSON.stringify(cats)+" · ajuste del dueño"+(nota?": "+nota:"")});
  res.json({ok:true});
});
app.get("/admin/kardex",authA,async(req,res)=>{
  // rango opcional: ?desde=YYYY-MM-DD&hasta=YYYY-MM-DD
  const d=String(req.query.desde||"").slice(0,10);
  const h=String(req.query.hasta||"").slice(0,10);
  const rango=/^\d{4}-\d{2}-\d{2}$/.test(d)&&/^\d{4}-\d{2}-\d{2}$/.test(h);
  let qk=db.from("kardex").select("*").order("id",{ascending:false});
  let qv=db.from("ventas").select("*").order("id",{ascending:false});
  if(rango){
    qk=qk.gte("creado",iniDia(d)).lte("creado",finDia(h)).limit(800);
    qv=qv.gte("creado",iniDia(d)).lte("creado",finDia(h)).limit(800);
  }else{ qk=qk.limit(150); qv=qv.limit(150); }
  const [kx,vt]=await Promise.all([qk,qv]).then(r=>[r[0].data||[],r[1].data||[]]);
  const rows=kx.concat(vt.map(v=>({conductor:v.conductor,tipo:"venta",
    detalle:v.tienda+" · S/"+Number(v.total||0).toFixed(2)+" · "+({efectivo:"💵 efectivo",credito:"📋 crédito",mixto:"🔀 mixto",yape:"📱 Yape"}[v.metodo]||v.metodo||"")
      +(Number(v.credito||0)>0?" · fiado S/"+Number(v.credito).toFixed(2):"")
      +(Number(v.abono||0)>0?" · cobró S/"+Number(v.abono).toFixed(2):"")
      +(v.resumen?" · "+v.resumen:""),creado:v.creado})))
    .sort((a,b)=>new Date(b.creado)-new Date(a.creado)).slice(0,rango?1200:250);
  res.json({ok:true,rows,desde:rango?d:null,hasta:rango?h:null});
});
app.get("/admin/gps",authA,async(req,res)=>{
  const{data:cs}=await db.from("conductores").select("usuario,nombre,tipo,camion,lat,lon,gps_fuente,gps_hora,gps_id").eq("activo",true);
  const lim=Date.now()-GPS_MIN*60000;
  res.json({ok:true,plataforma:GPS_PLAT||null,timeout_min:GPS_MIN,
    conductores:(cs||[]).filter(c=>c.lat&&c.lon).map(c=>({usuario:c.usuario,nombre:c.nombre,camion:c.camion,tipo:c.tipo,
      lat:c.lat,lon:c.lon,fuente:c.gps_fuente,hora:c.gps_hora,
      min:c.gps_hora?Math.round((Date.now()-new Date(c.gps_hora).getTime())/60000):null,
      activo:c.gps_hora?new Date(c.gps_hora).getTime()>lim:false}))});
});
app.get("/admin/gps/dispositivos",authA,async(req,res)=>{
  if(!GPS_PLAT)return res.json({ok:false,error:"No hay plataforma GPS configurada (variable GPS_PLATFORM)"});
  try{
    if(GPS_PLAT==="traccar"){
      const auth=Buffer.from(`${process.env.GPS_USER}:${process.env.GPS_PASSWORD}`).toString("base64");
      const r=await fetch(`${process.env.GPS_API_URL}/api/devices`,{headers:{Authorization:`Basic ${auth}`}});
      if(r.status===401)return res.json({ok:false,error:"Usuario o contraseña incorrectos en Railway (GPS_USER/GPS_PASSWORD)"});
      if(!r.ok)return res.json({ok:false,error:"Traccar respondió "+r.status+" — puede que la API no esté habilitada en esa cuenta"});
      const d=await r.json();
      return res.json({ok:true,plataforma:"traccar",dispositivos:(d||[]).map(x=>({id:String(x.id),nombre:x.name||"",placa:x.uniqueId||"",estado:x.status||"",ultima:x.lastUpdate||null}))});
    }
    const pos=await obtenerGPS();
    res.json({ok:true,plataforma:GPS_PLAT,dispositivos:pos.map(p=>({id:p.gps_id,nombre:"(unidad "+p.gps_id+")",placa:"",estado:"",ultima:p.ts?new Date(p.ts).toISOString():null}))});
  }catch(e){res.json({ok:false,error:"No se pudo conectar: "+e.message+" — revisa GPS_API_URL"});}
});
app.get("/admin/gps/recorrido",authA,async(req,res)=>{
  const u=String(req.query.conductor||"");const d=String(req.query.fecha||hoy());
  const{data}=await db.from("posiciones").select("lat,lon,creado,vel").eq("conductor",u)
    .gte("creado",iniDia(d)).lte("creado",finDia(d)).order("creado").limit(2000);
  res.json({ok:true,puntos:data||[]});
});
app.post("/admin/conductores/:u/gpsid",authA,async(req,res)=>{
  await db.from("conductores").update({gps_id:limpia(req.body.gps_id,40)||null}).eq("usuario",req.params.u);
  res.json({ok:true});
});
// Limpieza: recorridos con más de 60 días
cron.schedule("30 3 * * *",async()=>{const l=new Date(Date.now()-60*86400000).toISOString();await db.from("posiciones").delete().lt("creado",l);},{timezone:"America/Lima"});

// Recordatorio semanal de respaldo
cron.schedule("0 8 * * 1",async()=>{
  try{
    const{data:p}=await db.from("params").select("kv").eq("id",2).maybeSingle();
    const ult=p&&p.kv&&p.kv.ultimo_respaldo?new Date(p.kv.ultimo_respaldo):null;
    const dias=ult?Math.round((Date.now()-ult.getTime())/86400000):999;
    if(dias>=7){
      await evento("respaldo","💾 Toca hacer respaldo",ult?("El último respaldo fue hace "+dias+" días. Descárgalo desde Exportar → Respaldo completo."):"Aún no has descargado ningún respaldo. Hazlo desde Exportar → Respaldo completo.","");
      avisarAdmin("💾 Recordatorio: descarga el respaldo del sistema (Exportar → Respaldo completo).");
    }
  }catch(e){console.error("cron respaldo:",e.message);}
},{timezone:"America/Lima"});

// Alerta: camión detenido 3 h sin vender (en horario de trabajo)
const ALERTA_QUIETO=new Map(); // evita repetir la alerta el mismo día
cron.schedule("*/20 * * * *",async()=>{
  try{
    const h=Number(new Date().toLocaleString("en-US",{hour:"2-digit",hour12:false,timeZone:"America/Lima"}));
    if(h<6||h>20)return;                       // solo en horario de trabajo
    const _pd=await getParams();
    const MIN=num(_pd.operacion&&_pd.operacion.min_detenido,5,720,0)||((num(process.env.ALERTA_QUIETO_H,1,12)||3)*60);
    const HORAS=MIN/60, HORAS_TXT=(MIN%60===0)?(MIN/60)+" h":MIN+" min";
    const desde=new Date(Date.now()-MIN*60000).toISOString();
    const{data:cs}=await db.from("conductores").select("usuario,nombre").eq("activo",true);
    const quietos=[];
    for(const c of (cs||[])){
      const hoyKey=c.usuario+"|"+hoy();
      if(ALERTA_QUIETO.get(hoyKey))continue;
      const{data:pos}=await db.from("posiciones").select("lat,lon,creado").eq("conductor",c.usuario).gte("creado",desde).order("creado");
      if(!pos||pos.length<3)continue;          // sin datos suficientes, no inventamos alertas
      let movio=false;
      for(const p of pos){
        const d=Math.hypot((p.lat-pos[0].lat)*111,(p.lon-pos[0].lon)*105); // km aprox
        if(d>0.3){movio=true;break;}
      }
      if(movio)continue;
      const{data:vts}=await db.from("ventas").select("id").eq("conductor",c.usuario).gte("creado",desde).limit(1);
      if(vts&&vts.length)continue;             // vendió: no hay problema
      ALERTA_QUIETO.set(hoyKey,true);
      quietos.push(c.nombre);
    }
    if(quietos.length){
      const lista=quietos.join(", ");
      await evento("camion_detenido","🛑 "+(quietos.length>1?quietos.length+" camiones detenidos":"Camión detenido — "+lista),
        lista+": "+HORAS_TXT+" en el mismo lugar y sin registrar ventas. Puede ser avería, bloqueo de vía o un problema.","");
      avisarAdmin("🛑 "+HORAS_TXT+" detenido(s) y sin ventas: "+lista,"camion_detenido");
    }
  }catch(e){console.error("cron quieto:",e.message);}
},{timezone:"America/Lima"});

// Aviso diario: tiendas que dejaron de comprar
cron.schedule("0 7 * * *",async()=>{
  try{
    const p=await getParams(),D=num(p.inactiva_dias,1,365)||10;
    const{data:tds}=await db.from("tiendas").select("id,nombre").eq("act",true);
    const{data:vs}=await db.from("ventas").select("tienda_id,creado").order("creado",{ascending:false}).limit(2000);
    const ult={};(vs||[]).forEach(v=>{if(v.tienda_id&&!(v.tienda_id in ult))ult[v.tienda_id]=v.creado;});
    const frias=(tds||[]).filter(t=>{const u=ult[t.id];return u?((Date.now()-new Date(u).getTime())/86400000)>=D:false;});
    if(frias.length){await evento("inactivas","😴 "+frias.length+" tienda(s) sin comprar hace "+D+"+ días",frias.map(t=>t.nombre).join(", ")+". Revisa si conviene visitarlas o si dejaron de trabajar contigo.","");
      avisarAdmin("😴 "+frias.length+" tienda(s) sin comprar hace "+D+"+ días: "+frias.map(t=>t.nombre).slice(0,8).join(", "),"inactivas");}   /* 177 */
  }catch(e){console.error("cron inactivas:",e.message);}
},{timezone:"America/Lima"});

// ════════ INFORME DIARIO 22:00 (hora Perú) ════════
cron.schedule("0 * * * *",async()=>{
  try{
    /* 175 · corre cada hora y solo actúa a la hora elegida en Configuración (antes fija a las 22) */
    const _pi=await getParams(),HI=num(_pi.operacion&&_pi.operacion.hora_informe,0,23,22);
    const hLima=Number(new Date().toLocaleString("en-US",{hour:"2-digit",hour12:false,timeZone:"America/Lima"}))%24;
    if(hLima!==HI)return;
    const{data:vs0}=await db.from("ventas").select("*").gte("creado",iniDia(hoy()));
    const IND=await independientes();   /* 183 */
    const vs=(vs0||[]).filter(v=>!v.anulada&&!IND.has(v.conductor));
    const tot=(vs||[]).reduce((s,v)=>s+Number(v.total||0),0);
    const por={};(vs||[]).forEach(v=>{por[v.conductor]=(por[v.conductor]||0)+Number(v.total||0)});
    let analisis="";
    if(anthropic){try{const r=await anthropic.messages.create({model:MODELO_IA,max_tokens:300,system:"Eres analista de una distribuidora de panes en Perú. Un párrafo ejecutivo en español, máx 80 palabras: lo importante del día, alertas y qué mirar mañana.",messages:[{role:"user",content:JSON.stringify({fecha:hoy(),total:tot,porConductor:por,ventas:(vs||[]).length})}]});analisis="\n\nANÁLISIS\n"+r.content[0].text;}catch(e){console.log("IA informe:",e.message);}}
    await avisarAdmin("📊 INFORME "+hoy()+"\nVentas: S/"+tot.toFixed(2)+" ("+(vs||[]).length+" entregas)\n"+Object.entries(por).map(([k,v])=>k+": S/"+v.toFixed(2)).join("\n")+analisis,"informe",true);
  }catch(e){console.error("Informe:",e.message);}
},{timezone:"America/Lima"});
// Limpieza de logs a 30 días
cron.schedule("0 3 * * *",async()=>{const lim=new Date(Date.now()-30*86400000).toISOString();await db.from("logs").delete().lt("creado",lim).neq("tipo","admin");},{timezone:"America/Lima"});

/* 175 · ruta que no existe → JSON (antes HTML 404: la app lo confundía con falta de señal) */
app.use((req,res)=>res.status(404).json({ok:false,error:"Ruta no existe en el servidor: "+req.method+" "+req.path}));
app.use((err,req,res,next)=>{console.error("ERROR "+req.method+" "+req.path+":",err&&err.message);
  if(res.headersSent)return;res.status(err&&err.status||500).json({ok:false,error:(err&&err.status===400)?"Datos inválidos (JSON)":"Error interno del servidor"});});
const PORT=process.env.PORT||3000;
app.listen(PORT,()=>console.log("Servidor v5.0 en puerto "+PORT+" · IA solo informes · Twilio solo alertas al dueño"));
