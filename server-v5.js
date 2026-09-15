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

const app=express();
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
const NO_TOCAR=new Set(["pass","actual","nueva","clave","foto"]);
function sanea(o,prof){if(prof>4)return null;
 if(typeof o==="string")return limpia(o,300);
 if(Array.isArray(o))return o.slice(0,300).map(x=>sanea(x,prof+1));
 if(o&&typeof o==="object"){const r={};let n=0;for(const k of Object.keys(o)){if(++n>60)break;const kk=String(k).slice(0,40);r[kk]=NO_TOCAR.has(kk)?o[k]:sanea(o[k],prof+1);}return r;}
 return o;}
app.use((req,res,next)=>{try{if(req.body&&typeof req.body==="object")req.body=sanea(req.body,0);}catch(e){}next();});
const authLimiter=rateLimit({windowMs:5*60*1000,max:25});
app.set("trust proxy",1); // IP real detrás de Railway (bloqueos y rate-limit correctos)
if((process.env.JWT_SECRET||"").length<24){console.error("JWT_SECRET demasiado corto: usa una frase de 24+ caracteres");process.exit(1);}
const {timingSafeEqual}=require("crypto");
const safeEq=(x,y)=>{x=Buffer.from(String(x));y=Buffer.from(String(y));return x.length===y.length&&timingSafeEqual(x,y);};
const USR_RE=/^[a-z0-9_]{3,20}$/;
const limpia=(s,max)=>String(s??"").replace(/[<>`]/g,"").replace(/[\u0000-\u001f\u007f]/g," ").trim().slice(0,max||300);
const num=(v,min,max)=>{v=Number(v);if(!isFinite(v))v=0;if(min!=null&&v<min)v=min;if(max!=null&&v>max)v=max;return v;};
const fotoOK=f=>typeof f==="string"&&/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(f)&&f.length<160000;
const CATS_OK=["sm","bianka","panes","molde","especiales","chifones","tortas","queques"];
const catsOK=o=>{if(!o||typeof o!=="object")return null;const r={};CATS_OK.forEach(k=>{if(o[k]!=null)r[k]=num(o[k],0,99999)});return Object.keys(r).length?r:null;};
// Intentos fallidos por IP+usuario (además del rate limit)
const FALLOS=new Map();
const kIP=req=>String(req.ip||"?");
const falla=k=>{const f=FALLOS.get(k)||{n:0,ts:0};f.n++;f.ts=Date.now();FALLOS.set(k,f);};
const bloqueado=k=>{const f=FALLOS.get(k);return !!f&&f.n>=5&&(Date.now()-f.ts)<15*60*1000;};
const limpiaFallo=k=>FALLOS.delete(k);
setInterval(()=>{const lim=Date.now()-30*60*1000;for(const[k,f]of FALLOS)if(f.ts<lim)FALLOS.delete(k);},10*60*1000);

// ── helpers ──
const hoy=()=>new Date().toISOString().slice(0,10);
const horaPE=()=>new Date().toLocaleTimeString("es-PE",{hour:"2-digit",minute:"2-digit",timeZone:"America/Lima"});
async function avisarAdmin(msg){
  if(twilioC&&ADMIN_TEL){try{await twilioC.messages.create({from:process.env.TWILIO_WHATSAPP_FROM||"whatsapp:+14155238886",to:"whatsapp:+"+ADMIN_TEL,body:msg});}catch(e){console.log("Twilio:",e.message);}}
  else console.log("[ALERTA ADMIN]",msg);
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

function pipSrv(lat,lon,poly){let d=false;for(let i=0,j=poly.length-1;i<poly.length;j=i++){const yi=poly[i][0],xi=poly[i][1],yj=poly[j][0],xj=poly[j][1];if(((yi>lat)!==(yj>lat))&&(lon<(xj-xi)*(lat-yi)/(yj-yi)+xi))d=!d;}return d;}
let ZONAS_CACHE={t:0,z:[]};
async function zonasVivas(){if(Date.now()-ZONAS_CACHE.t<60000)return ZONAS_CACHE.z;const p=await getParams();ZONAS_CACHE={t:Date.now(),z:(p.zonas||[])};return ZONAS_CACHE.z;}
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
    "app-conductor.html":["v5no304","v5origen","v5notipos","v5stockp","cpGetPrecio(cat.id,p.id)"],
    "admin-dashboard.html":["v5sinprestamo","v5pdprecios","v5dupids","v5catipo"]
  };
  const out={servidor:{etag_desactivado:app.get("etag")===false,consultas_en_paralelo:true,hora:new Date().toISOString()},archivos:{}};
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
async function moverStock(conductor,cambios,motivo,ref){
  if(!conductor||!cambios||!Object.keys(cambios).length)return;
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
app.get("/conductor/stock",authC,async(req,res)=>{
  res.set("Cache-Control","no-store");
  const s=await leerStock(req.cond.u);
  res.json({ok:true,prods:s.prods,base:s.base,por_categoria:await porCategoria(s.prods)});
});
app.post("/conductor/stock/ajuste",authC,async(req,res)=>{
  const p=req.body.prods;
  if(!p||typeof p!=="object")return res.status(400).json({ok:false,error:"Faltan datos"});
  const cambios={};Object.keys(p).slice(0,300).forEach(id=>{cambios[id]=num(p[id],-9999,9999)});
  await moverStock(req.cond.u,cambios,limpia(req.body.motivo,20)||"ajuste",null);
  const s=await leerStock(req.cond.u);
  res.json({ok:true,prods:s.prods});
});
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
  const [vts,mov,trs,gas,perd]=await Promise.all([
    db.from("ventas").select("*").eq("conductor",u).gte("creado",inicio).lte("creado",fin),
    db.from("stock_mov").select("motivo,delta").eq("conductor",u).gte("creado",inicio),
    db.from("traspasos").select("*").or("de.eq."+u+",para.eq."+u).gte("creado",inicio),
    db.from("gastos").select("categoria,monto,detalle").eq("conductor",u).gte("creado",inicio),
    db.from("perdidas").select("motivo,valor,detalle,tienda").eq("conductor",u).gte("creado",inicio)
  ]).then(r=>r.map(x=>x.data||[]));
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
  const resumen={
    conductor:u,nombre:yo.nombre||u,inicio,fin,
    dias:Math.max(1,Math.round((new Date(fin)-new Date(inicio))/86400000)),
    ventas:{n:vts.length,total:sum(vts,v=>v.total),efectivo,yape,fiado,abonos},
    efectivo_esperado:Math.round((efectivo+abonos-gastos)*100)/100,
    gastos:{total:gastos,detalle:gas},
    perdidas:{total:perdidas,n:perd.length,detalle:perd},
    mercaderia:{cargado:mSum("carga"),recibido_en_ruta:mSum("traspaso_recibe"),
      vendido:mSum("venta"),devuelto:mSum("traspaso_envia"),queda:quedan,
      destino_restante:quedan?destino:null},
    traspasos:trs.map(t=>({id:t.id,de:t.de,para:t.para,estado:t.estado,items:t.items})),
    cerrado_por_dueno:true
  };
  const decl=num(req.body.efectivo_declarado,0,999999);
  const dif=Math.round((decl-resumen.efectivo_esperado)*100)/100;
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
  res.json({ok:true,token:jwt.sign({u,tipo:c.tipo},SECRET,{expiresIn:"30d"}),nombre:c.nombre,tipo:c.tipo,camion:c.camion});
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
  res.json({ok:true,token:jwt.sign({u,tipo:c.tipo},SECRET,{expiresIn:"30d"}),nombre:c.nombre,tipo:c.tipo,camion:c.camion});
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
    db.from("pedidos").select("*").eq("fecha",hoy()).eq("conductor",u).eq("estado","pendiente"),
    db.from("ventas").select("tienda_id,creado,total,resumen,items").order("creado",{ascending:false}).limit(400),
    db.from("conductores").select("usuario,nombre,tipo").eq("activo",true).neq("usuario",u),
    db.from("avisos").select("*").or(`para.eq.${u},para.eq.todos`).order("id",{ascending:false}).limit(20),
    db.from("avisos_leidos").select("aviso_id").eq("usuario",u),
    db.from("creditos_mov").select("tipo,monto,por,creado").eq("por",u).gte("creado",hoy()+"T00:00:00"),
    db.from("conductores").select("lat,lon,gps_fuente,gps_hora,en_turno,turno_ini").eq("usuario",u).maybeSingle(),
    db.from("cargas").select("*").eq("conductor",u).eq("estado","pendiente").order("id",{ascending:false}).limit(1).maybeSingle(),
    db.from("traspasos").select("*").eq("para",u).in("estado",["pendiente","parcial"]),
    db.from("traspasos").select("*").eq("de",u).in("estado",["pendiente","parcial"]),
    db.from("traspasos").select("*").eq("estado","completado").gte("creado",lim3).or(`de.eq.${u},para.eq.${u}`),
    db.from("catalogo").select("id,cat,nombre,precio,precios,costo,activo,no_tipos").or("activo.is.null,activo.eq.true"),
    db.from("categorias").select("*").eq("activa",true).order("orden")
  ]).then(rs=>rs.map(x=>x&&x.data));
  const params=await getParams();await zonasVivas();
          const tiendas=(tds||[]).map(t=>{
    const vs=(ultV||[]).filter(v=>v.tienda_id===t.id).slice(0,5);
    const UMB=num(params.umbral_repo,1,100000)||40, RESTA=num(params.repo_resta_parcial,0,30)||2;
    const vsAll=(ultV||[]).filter(v=>v.tienda_id===t.id);
    const iBig=vsAll.findIndex(v=>Number(v.total||0)>=UMB);
    const baseV=iBig>=0?vsAll[iBig]:(vsAll.length?vsAll[vsAll.length-1]:null);
    const nBajas=iBig>=0?iBig:vsAll.length;   // compras bajas posteriores a la última compra "buena"
    const diasBase=baseV?Math.round((Date.now()-new Date(baseV.creado).getTime())/86400000):(t.dr??3);
    const dr=Math.max(0,diasBase-RESTA*nBajas-(t.dr_ajuste||0));
    const ultBaja=(vsAll.length&&Number(vsAll[0].total||0)<UMB)?Number(vsAll[0].total||0):null;
    const vo=(vHoy||[]).find(v=>v.tienda_id===t.id&&v.conductor!==u&&v.tipo==="venta");
    const pd=(peds||[]).find(p=>(p.tienda_id&&p.tienda_id===t.id)||(p.tienda&&String(p.tienda).toLowerCase().trim()===String(t.nombre).toLowerCase().trim()));
    return {n:t.nombre,z:t.zona||"—",tp:t.tipo||"bodega",d:t.dueno||"—",tel:t.tel||"—",
      e:vs.length&&vs[0].creado.slice(0,10)===hoy()?"completada":"pendiente",
      cr:!!t.cr,sa:Number(t.sa||0),li:Number(t.li||params.limite_credito||230),di:"—",
      no:t.notas||"",ab:true,lat:t.lat,lon:t.lon,dr,vip:!!t.vip,act:true,
      nueva:!!t.nueva,verificada:!!t.verificada,foto:t.foto||null,id:t.id,
      h:vs.map(v=>({f:new Date(v.creado).toLocaleDateString("es-PE"),p:v.resumen||"",m:Number(v.total)})),
      ultima_compra:(vs[0]&&Array.isArray(vs[0].items))?vs[0].items.filter(x=>x&&x.id).map(x=>({id:x.id,n:x.n,c:num(x.c,0,9999)})):[],
      compras:(vs||[]).slice(0,2).map(v=>({id:v.id,fecha:v.creado,total:Number(v.total||0),
        items:(Array.isArray(v.items)?v.items:[]).filter(x=>x&&x.id).map(x=>({id:x.id,n:x.n,c:num(x.c,0,9999),pu:num(x.pu,0,10000)}))})),
      pedido:pd?{items:pd.items,hora:pd.hora,nota:pd.nota||""}:undefined,
      pedidoHoy:!!pd,
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
  res.json({ok:true,params,turno_ini:(yo&&yo.turno_ini)||null,en_turno:!!(yo&&yo.en_turno),catalogo:cat||[],categorias:cats||[],tiendas,avisos,colegas:(cols||[]).map(x=>({usuario:x.usuario,nombre:x.nombre,tipo:x.tipo})),
    dia:{fiado:fiadoHoy,cobrado:cobradoHoy},
    gps_camion:(yo&&yo.lat&&yo.gps_fuente&&yo.gps_fuente!=="celular")?{lat:yo.lat,lon:yo.lon,fuente:yo.gps_fuente,hora:yo.gps_hora}:null,
    carga_pendiente:cg?{id:cg.id,items:cg.items,prods:cg.prods||null,detalle:cg.detalle||null}:null,
    traspasos_entrantes:(trs||[]).map(t=>({id:String(t.id),de:t.de_nombre||t.de,items:t.items,estado:t.estado,yo_confirme:!!t.conf_para,otro_confirmo:!!t.conf_de})),
    traspasos_completados:(trsOk||[]).map(t=>({id:String(t.id),items:t.items,rol:t.para===u?"recibe":"entrega",otro:t.para===u?(t.de_nombre||t.de):t.para})),
    traspasos_salientes:(trsOut||[]).map(t=>({id:String(t.id),para:t.para,items:t.items,estado:t.estado,yo_confirme:!!t.conf_de,otro_confirmo:!!t.conf_para}))});
});

// ════════ OPERACIÓN DEL CONDUCTOR ════════
app.post("/ventas",authC,async(req,res)=>{
  const{tienda,items,total,metodo}=req.body;
  let t=null;
  if(req.body.tienda_id){const{data:x}=await db.from("tiendas").select("*").eq("id",req.body.tienda_id).maybeSingle();t=x||null;}
  if(!t){const{data:x}=await db.from("tiendas").select("*").ilike("nombre",String(tienda||"").trim()).maybeSingle();t=x||null;}
  if(!t)return res.status(400).json({ok:false,error:"No identifiqué la tienda: "+tienda});
  const resumen=(items||[]).map(x=>`${x.n} x${x.c}`).join(", ");
  const{data:v}=await db.from("ventas").insert({efectivo:num(req.body.efectivo,0,999999),credito:num(req.body.credito,0,999999),abono:num(req.body.abono,0,999999),tienda_id:t?t.id:null,tienda:tienda,conductor:req.cond.u,items:items||[],total:num(total,0,999999),metodo:(["efectivo","yape","credito","mixto"].includes(metodo)?metodo:"efectivo"),resumen}).select().single();
  // ¿venta después de haber liquidado? (cola que llegó tarde, o venta real fuera de viaje)
  let fueraDeTurno=false;
  try{
    const{data:yoT}=await db.from("conductores").select("en_turno,turno_ini").eq("usuario",req.cond.u).maybeSingle();
    fueraDeTurno=!(yoT&&yoT.en_turno);
    if(fueraDeTurno&&v){
      const{data:ult}=await db.from("liquidaciones").select("id,resumen").eq("conductor",req.cond.u).order("id",{ascending:false}).limit(1).maybeSingle();
      await db.from("ventas").update({post_liq:true,liq_id:ult?ult.id:null}).eq("id",v.id);
      await avisarAdmin("⚠️ Venta registrada FUERA DE VIAJE — "+req.cond.u
        +"\nTienda: "+(t&&t.nombre||"—")+" · S/"+Number(total||0).toFixed(2)+" ("+(metodo||"")+")"
        +"\nSe anota como ajuste de la liquidación #"+(ult?ult.id:"—")+", que no se modifica."
        +"\nRevisa si corresponde cobrar aparte.");
      await db.from("logs").insert({tipo:"venta_post_liq",detalle:req.cond.u+" vendió S/"+Number(total||0).toFixed(2)+" fuera de turno"});
    }
  }catch(e){console.error("post_liq:",e.message);}
  // descontar del stock lo que salió del camión
  try{
    const salida={};
    (Array.isArray(req.body.items)?req.body.items:[]).forEach(it=>{if(it&&it.id)salida[it.id]=-(num(it.c,0,9999));});
    if(Object.keys(salida).length)await moverStock(req.cond.u,salida,"venta",v&&v.id);
  }catch(e){console.error("stock venta:",e.message);}
  if(t)await db.from("visitas").insert({tienda_id:t.id,tienda:t.nombre,conductor:req.cond.u,tipo:"venta",fecha:hoy(),hora:horaPE()});
  if(t&&t.dr_ajuste)await db.from("tiendas").update({dr_ajuste:0}).eq("id",t.id);
  const fiado=num(req.body.credito,0,999999)||((metodo==="credito")?num(total,0,999999):0);
  const abono=num(req.body.abono,0,999999);
  if(abono>0){
    await db.from("creditos_mov").insert({tienda_id:t.id,tipo:"abono",monto:abono,detalle:"Cobro en visita #"+v.id,por:req.cond.u});
    await db.from("tiendas").update({sa:Math.max(0,Number(t.sa||0)-abono)}).eq("id",t.id);
  }
  if(fiado>0&&!t.cr)await evento("credito_sin_permiso","⚠️ Venta al crédito en tienda sin crédito habilitado",
    t.nombre+" · S/"+fiado.toFixed(2)+" · conductor "+req.cond.u,String(t.id));
  if(fiado>0){
    const{data:t2}=await db.from("tiendas").select("sa").eq("id",t.id).maybeSingle();
    await db.from("creditos_mov").insert({tienda_id:t.id,tipo:"cargo",monto:fiado,
      detalle:"Venta "+(metodo==="mixto"?"mixta":"a crédito")+" #"+v.id,por:req.cond.u});
    await db.from("tiendas").update({sa:Number((t2&&t2.sa)||t.sa||0)+fiado}).eq("id",t.id);
  }
  try{await db.from("kardex").insert({conductor:req.cond.u,tipo:"venta_detalle",
    detalle:t.nombre+" · S/"+Number(total||0).toFixed(2)+" ("+(metodo||"efectivo")+")"+(fiado>0?" · fiado S/"+fiado.toFixed(2):"")});}catch(e){}
  res.json({ok:true,id:v.id});
});
app.post("/visitas",authC,async(req,res)=>{
  const t=await tiendaPorNombre(req.body.tienda||"");
  await db.from("visitas").insert({tienda_id:t?t.id:null,tienda:req.body.tienda,conductor:req.cond.u,tipo:(["venta","fallida","no_quiso","registro"].includes(req.body.tipo)?req.body.tipo:"fallida"),fecha:hoy(),hora:horaPE()});
  if((req.body.tipo||"")==="fallida")await evento("visita","🚫 Visita fallida — "+req.body.tienda,req.cond.u+" la encontró cerrada. Reprogramada para mañana con prioridad; la reposición sigue contando.",t?t.id:"");
  if((req.body.tipo||"")==="no_quiso"&&t){
    await db.from("tiendas").update({dr_ajuste:num((t.dr_ajuste||0)+2,0,60)}).eq("id",t.id);
    await evento("visita","🙅 No quiso comprar — "+req.body.tienda,req.cond.u+" ofreció y el dueño decidió no llevar. Se le restan 2 días al contador de reposición.",t.id);
  }
  if((req.body.tipo||"")==="venta_fuera_zona"){await evento("zona","📍 Venta fuera de zona — "+req.body.tienda,req.cond.u+" registró una venta fuera de las zonas dibujadas ("+(req.body.lat||"?")+", "+(req.body.lon||"?")+").",t?t.id:"");avisarAdmin("📍 Venta fuera de zona: "+req.body.tienda+" por "+req.cond.u);}
  res.json({ok:true});
});
app.post("/tiendas",authC,async(req,res)=>{
  const b=req.body;
  const{data:t,error}=await db.from("tiendas").insert({nombre:b.n,zona:b.z,tipo:b.tp,dueno:b.d,tel:String(b.tel||"").replace(/\D/g,"").slice(0,15),notas:b.no||"",hora_ini:limpia(b.h_ini,5),hora_fin:limpia(b.h_fin,5),dias_no:limpia(b.dias_no,30),lat:(b.lat==null?null:num(b.lat,-90,90)),lon:(b.lon==null?null:num(b.lon,-180,180)),foto:fotoOK(b.foto)?b.foto:null,cr:false,sa:0,li:0,vip:false,act:true,nueva:true,verificada:false,conductor_reg:req.cond.u}).select().single();
  if(error)return res.status(500).json({ok:false,error:error.message});
  await evento("tienda_nueva","🆕 Tienda nueva por verificar — "+b.n,"Registrada por "+req.cond.u+" en "+(b.z||"—")+". Contado habilitado; crédito bloqueado hasta que la verifiques.",t.id);
  avisarAdmin("🆕 Tienda nueva por verificar: "+b.n+" ("+(b.z||"—")+") — registrada por "+req.cond.u);
  res.json({ok:true,id:t.id});
});
app.post("/correcciones",authC,async(req,res)=>{
  const{data:c}=await db.from("correcciones").insert({tienda:req.body.tienda,referencia:req.body.referencia,monto_correcto:Number(req.body.monto_correcto)||0,motivo:req.body.motivo,conductor:req.cond.u,estado:"pendiente"}).select().single();
  await evento("correccion","✎ Corrección propuesta — "+req.body.tienda,req.body.referencia+" → S/"+Number(req.body.monto_correcto||0).toFixed(2)+". Motivo: "+req.body.motivo+" (por "+req.cond.u+")",c.id);
  res.json({ok:true,id:c.id});
});
app.post("/traspasos",authC,async(req,res)=>{
  const prodsT=limpiaProds(req.body.prods||req.body.items);
  const itemsT=await porCategoria(prodsT);
  const{data:t}=await db.from("traspasos").insert({de:req.body.de,de_nombre:req.body.de_nombre||req.body.de,para:req.cond.u,prods:prodsT,items:itemsT,estado:"pendiente"}).select().single();
  await avisoA(req.body.de,"↔ "+req.cond.u+" te solicita traspaso: "+Object.entries(req.body.items||{}).map(([k,v])=>k+"×"+v).join(", ")+". Si aceptas, entrégalo y él lo confirmará en su app.");
  await evento("traspaso","↔ Solicitud de traspaso",req.cond.u+" pidió a "+(req.body.de_nombre||req.body.de)+". Se mueve solo cuando el receptor confirme.",t.id);
  res.json({ok:true,id:t.id});
});
app.post("/traspasos/estado",authC,async(req,res)=>{
  const{data:t}=await db.from("traspasos").select("*").eq("id",req.body.id).maybeSingle();
  if(!t)return res.status(404).json({ok:false});
  const yo=req.cond.u, esDe=(t.de===yo), esPara=(t.para===yo);
  if(!esDe&&!esPara)return res.status(403).json({ok:false,error:"No es tu traspaso"});
  if(req.body.accion==="rechazar"){
    await db.from("traspasos").update({estado:"rechazado"}).eq("id",t.id);
    await avisoA(esDe?t.para:t.de,"✗ "+yo+" rechazó el traspaso.");
    await evento("traspaso","↔ Traspaso rechazado",(t.de_nombre||t.de)+" → "+t.para+" (rechazó "+yo+")",t.id);
    return res.json({ok:true,estado:"rechazado"});
  }
  const upd={};
  if(esDe)upd.conf_de=true; if(esPara)upd.conf_para=true;
  const cDe=upd.conf_de||t.conf_de, cPara=upd.conf_para||t.conf_para;
  upd.estado=(cDe&&cPara)?"completado":"parcial";
  // cuando ambos confirman, la mercadería cambia de manos en el inventario
  if(upd.estado==="completado"&&t.estado!=="completado"){
    const pr=limpiaProds(t.prods);
    if(Object.keys(pr).length){
      const menos={},mas={};
      Object.keys(pr).forEach(id=>{menos[id]=-pr[id];mas[id]=pr[id];});
      await moverStock(t.de,menos,"traspaso_envia",t.id);
      await moverStock(t.para,mas,"traspaso_recibe",t.id);
    }
  }
  await db.from("traspasos").update(upd).eq("id",t.id);
  if(cDe&&cPara){
    const det=JSON.stringify(t.items);
    if(t.de==="almacen")await db.from("kardex").insert({conductor:"almacen",tipo:"almacen_salida",detalle:det+" · entregado a "+t.para});
    if(t.para==="almacen")await db.from("kardex").insert({conductor:"almacen",tipo:"almacen_retorno",detalle:det+" · recibido de "+t.de});
    await db.from("kardex").insert({conductor:t.para,tipo:"traspaso_in",detalle:"De "+(t.de_nombre||t.de)+": "+det});
    await db.from("kardex").insert({conductor:t.de,tipo:"traspaso_out",detalle:"Hacia "+t.para+": "+det});
    await avisoA(t.de,"✓ Traspaso completado con "+t.para+": ambos confirmaron.");
    await avisoA(t.para,"✓ Traspaso completado con "+(t.de_nombre||t.de)+": ambos confirmaron. Ya está en tu carga.");
    await evento("traspaso","↔ Traspaso completado",(t.de_nombre||t.de)+" → "+t.para+" — confirmado por ambos.",t.id);
  }else{
    const falta=cDe?t.para:t.de;
    await avisoA(falta,"↔ "+yo+" ya confirmó su parte del traspaso. Falta la tuya para que la mercadería se mueva.");
  }
  res.json({ok:true,estado:upd.estado});
});
app.post("/cargas/confirmar",authC,async(req,res)=>{
  const{data:c}=await db.from("cargas").select("*").eq("id",req.body.id).maybeSingle();
  if(c){
    await db.from("cargas").update({estado:req.body.conforme?"confirmada":"con_diferencias",items_final:catsOK(req.body.items)||c.items,motivo:req.body.motivo||""}).eq("id",c.id);
    await db.from("kardex").insert({conductor:req.cond.u,tipo:"carga_inicial",detalle:JSON.stringify(req.body.items||c.items)});
    // el detalle por producto entra al stock del camión
    const prodsCarga=(req.body.prods&&typeof req.body.prods==="object")?req.body.prods:(c.prods||null);
    if(prodsCarga)await moverStock(req.cond.u,prodsCarga,"carga",c.id);
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
      avisarAdmin("📦 Carga con diferencias ("+req.cond.u+"): "+(req.body.motivo||""));
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
  try{
    const p=req.body.prods;
    if(p&&typeof p==="object"){
      const menos={};Object.keys(p).forEach(id=>{menos[id]=-num(p[id],0,9999)});
      await moverStock(req.cond.u,menos,limpia(req.body.motivo,20)||"perdida",null);
    }
  }catch(e){}
  const motivo=limpia(req.body.motivo,40)||"otro";
  const val=num(req.body.valor,0,99999);
  await db.from("kardex").insert({conductor:req.cond.u,tipo:"perdida",
    detalle:motivo+" · S/"+val.toFixed(2)+(req.body.detalle?" · "+limpia(req.body.detalle,120):"")+(req.body.tienda?" · "+limpia(req.body.tienda,60):"")});
  res.json({ok:true});
});
app.get("/admin/cierres",authA,async(req,res)=>{
  const{data}=await db.from("liquidaciones").select("*").order("id",{ascending:false}).limit(60);
  res.json({ok:true,cierres:data||[]});
});
app.post("/gastos",authC,async(req,res)=>{
  const cat=["combustible","comida","peaje","mecanico","hospedaje","otros"].includes(req.body.categoria)?req.body.categoria:"otros";
  const monto=num(req.body.monto,0,99999);
  await db.from("kardex").insert({conductor:req.cond.u,tipo:"gasto_"+cat,detalle:"S/"+monto.toFixed(2)+(req.body.nota?" — "+limpia(req.body.nota,120):"")});
  const p=await getParams(),tope=num(p.tope_gastos,0,100000)||350;
  const{data:gs}=await db.from("kardex").select("tipo,detalle").eq("conductor",req.cond.u).like("tipo","gasto_%").order("id",{ascending:false}).limit(120);
  const sum=(gs||[]).filter(g=>g.tipo!=="gasto_combustible").reduce((s,g)=>s+(parseFloat(String(g.detalle).replace("S/",""))||0),0);
  if(sum>tope){
    await evento("gastos","💸 Gastos altos — "+req.cond.u,"Lleva S/"+sum.toFixed(2)+" en gastos que NO son combustible (tope S/"+tope+").",req.cond.u);
    avisarAdmin("💸 "+req.cond.u+" superó el tope de gastos no-combustible: S/"+sum.toFixed(2));
  }
  res.json({ok:true,acumulado_no_combustible:sum,tope});
});
app.post("/liquidaciones",authC,async(req,res)=>{
  const u=req.cond.u;
  // ── 1) el camión debe estar vacío ──
  const st=await leerStock(u);
  const quedan=Object.keys(st.prods).reduce((s,k)=>s+Number(st.prods[k]||0),0);
  if(quedan>0&&req.body.forzar!==true){
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
  const [vts,mov,trs,gas,perd,crd]=await Promise.all([
    db.from("ventas").select("*").eq("conductor",u).gte("creado",inicio).lte("creado",fin),
    db.from("stock_mov").select("motivo,delta,prod_id").eq("conductor",u).gte("creado",inicio),
    db.from("traspasos").select("*").or("de.eq."+u+",para.eq."+u).gte("creado",inicio),
    db.from("gastos").select("categoria,monto,detalle").eq("conductor",u).gte("creado",inicio),
    db.from("perdidas").select("motivo,valor,detalle,tienda").eq("conductor",u).gte("creado",inicio),
    db.from("creditos_mov").select("tipo,monto,tienda_id,detalle").eq("por",u).gte("creado",inicio)
  ]).then(r=>r.map(x=>x.data||[]));

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

  const resumen={
    conductor:u,nombre:(yo&&yo.nombre)||u,inicio,fin,
    dias:Math.max(1,Math.round((new Date(fin)-new Date(inicio))/86400000)),
    ventas:{n:vts.length,total:sum(vts,v=>v.total),efectivo,yape,fiado,abonos},
    efectivo_esperado:Math.round((efectivo+abonos-gastos)*100)/100,
    gastos:{total:gastos,detalle:gas},
    perdidas:{total:perdidas,n:perd.length,detalle:perd},
    mercaderia:{cargado,recibido_en_ruta:recibido,vendido:vendidoUnid,devuelto:devueltoAlmacen,queda:quedan},
    traspasos:trs.map(t=>({id:t.id,de:t.de,para:t.para,estado:t.estado,items:t.items})),
    deuda_generada:fiado,
    deuda_cobrada:abonos,
    creditos:crd
  };
  const decl=num(req.body.efectivo_declarado,0,999999);
  const dif=Math.round((decl-resumen.efectivo_esperado)*100)/100;

  const{data:l}=await db.from("liquidaciones").insert({
    conductor:u,dia:req.body.dia||{},kx:req.body.kx||[],
    inicio,fin,estado:"pendiente",efectivo_declarado:decl,diferencia:dif,
    resumen,nota:limpia(req.body.nota,300)||null
  }).select().single();

  // ── 4) marcar las ventas del viaje y cerrar el turno ──
  if(l){
    await db.from("ventas").update({liq_id:l.id}).eq("conductor",u).gte("creado",inicio).lte("creado",fin).is("liq_id",null);
    await db.from("conductores").update({en_turno:false,turno_hora:fin,turno_ini:null}).eq("usuario",u);
    await db.from("logs").insert({tipo:"turno",detalle:u+" termina (liquidación #"+l.id+")"});
  }
  await evento("liquidacion","💰 Liquidación de viaje — "+u,
    "Efectivo esperado S/"+resumen.efectivo_esperado.toFixed(2)+" · declarado S/"+decl.toFixed(2)+(dif?(" · diferencia S/"+dif.toFixed(2)):" · cuadra"),l&&l.id);
  avisarAdmin("💰 Liquidación de "+u+"\nEsperado S/"+resumen.efectivo_esperado.toFixed(2)
    +"\nDeclarado S/"+decl.toFixed(2)+(dif?("\n⚠️ Diferencia S/"+dif.toFixed(2)):"\n✓ Cuadra")
    +"\nFiado en el viaje S/"+fiado.toFixed(2)+" · Cobrado S/"+abonos.toFixed(2)
    +"\nConfírmala en el panel.");
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
  const{data:us}=await db.from("conductores").select("usuario,nombre,tipo,camion,activo,pass_hash,gps_id,en_turno,turno_hora");
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
  const{data:pds}=await db.from("pedidos").select("*").eq("fecha",hoy()).order("id",{ascending:false});
  const{data:vAd}=await db.from("ventas").select("tienda_id,creado").order("creado",{ascending:false}).limit(600);
  const _ult={};(vAd||[]).forEach(v=>{if(v.tienda_id&&!( v.tienda_id in _ult))_ult[v.tienda_id]=v.creado;});
  const _diasT=(id,aj)=>Math.max(0,(_ult[id]?Math.round((Date.now()-new Date(_ult[id]).getTime())/86400000):3)-(aj||0));
  res.json({ok:true,
    resumen:{tiendas:(tds||[]).length,conductores:(us||[]).length,
      en_turno:(us||[]).filter(x=>(x.en_turno!==undefined&&x.en_turno!==null)?x.en_turno:turnoDe[x.usuario]).length,
      pedidos_hoy:(pds||[]).filter(p=>String(p.fecha||p.creado||"").slice(0,10)===hoy()).length,
      pedidos_pendientes:(pds||[]).filter(p=>p.estado!=="entregado").length},
    usuarios:(us||[]).map(u=>({usuario:u.usuario,nombre:u.nombre,tipo:u.tipo,camion:u.camion,activo:u.activo,estado:u.pass_hash?"con contraseña":"sin contraseña",gps_id:u.gps_id||"",en_turno:(u.en_turno!==undefined&&u.en_turno!==null)?!!u.en_turno:!!turnoDe[u.usuario]})),
    eventos:(evs||[]).map(e=>({tipo:e.tipo,titulo:e.titulo,desc:e.descripcion,ref:e.tipo==="tienda_nueva"||e.tipo==="correccion"?e.ref:String(e.id)})),
    tiendas:(tds||[]).map(t=>({id:t.id,n:t.nombre,z:t.zona,d:_diasT(t.id,t.dr_ajuste),sa:Number(t.sa||0),cr:!!t.cr,li:Number(t.li||0),vip:!!t.vip,act:t.act,nueva:!!t.nueva,verificada:!!t.verificada,conductor:t.conductor_reg,lat:t.lat,lon:t.lon,tel:t.tel,due:t.dueno,falta:[],mov:[]})),
    pedidos_hoy:(pds||[]).map(p=>({tienda:p.tienda,conductor:p.conductor,items:p.items,nota:p.nota,hora:p.hora})),
    params:await getParams()});
});
app.post("/admin/conductores",authA,async(req,res)=>{
  const u=String(req.body.usuario||"").toLowerCase().trim();
  if(!USR_RE.test(u))return res.status(400).json({ok:false,error:"Usuario inválido: 3-20 caracteres, minúsculas/números/_"});
  if(!req.body.nombre)return res.status(400).json({ok:false,error:"Faltan datos"});
  const{error}=await db.from("conductores").insert({usuario:u,nombre:req.body.nombre,tipo:(req.body.tipo==="paso"?"paso":"fijo"),camion:req.body.camion||"—",activo:true,pass_hash:null});
  if(error)return res.status(409).json({ok:false,error:"Ese usuario ya existe"});
  res.json({ok:true});
});
app.post("/admin/conductores/:u/editar",authA,async(req,res)=>{
  const upd={};
  if(req.body.nombre)upd.nombre=limpia(req.body.nombre,60);
  if(req.body.camion!=null)upd.camion=limpia(req.body.camion,20);
  if(req.body.gps_id!=null)upd.gps_id=limpia(req.body.gps_id,40)||null;
  if(req.body.tipo)upd.tipo=(req.body.tipo==="paso"?"paso":"fijo");
  if(!Object.keys(upd).length)return res.status(400).json({ok:false,error:"Nada que cambiar"});
  await db.from("conductores").update(upd).eq("usuario",req.params.u);
  await db.from("logs").insert({tipo:"admin",detalle:"Editó al conductor @"+req.params.u+": "+Object.keys(upd).join(", ")});
  res.json({ok:true});
});
app.post("/admin/conductores/:u/reset",authA,async(req,res)=>{await db.from("conductores").update({pass_hash:null}).eq("usuario",req.params.u);
  await db.from("logs").insert({tipo:"admin",detalle:"Reseteó contraseña de @"+req.params.u});res.json({ok:true});});
app.post("/admin/conductores/:u/activo",authA,async(req,res)=>{await db.from("conductores").update({activo:!!req.body.activo}).eq("usuario",req.params.u);res.json({ok:true});});
app.post("/avisos",authA,async(req,res)=>{await avisoA((req.body.para==="todos"||USR_RE.test(req.body.para||""))?req.body.para:"todos",String(req.body.txt||""));res.json({ok:true});});
app.post("/pedidos",authA,async(req,res)=>{
  let t=await tiendaPorNombre(req.body.tienda||"");
  if(!t&&req.body.tienda){const{data:aprox}=await db.from("tiendas").select("id,nombre").ilike("nombre","%"+String(req.body.tienda).slice(0,20)+"%").limit(1);t=(aprox||[])[0]||null;}
  await db.from("pedidos").insert({tienda_id:t?t.id:null,tienda:req.body.tienda,conductor:req.body.conductor,items:(Array.isArray(req.body.items)?req.body.items.slice(0,60):[]).map(x=>({p:String(x.p||"").slice(0,60),c:num(x.c,1,999)})),nota:req.body.nota||"",hora:req.body.hora||horaPE(),fecha:hoy(),estado:"pendiente"});
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
  let{data:nc,error:eIns}=await db.from("cargas").insert({conductor:cond,items,prods,detalle:req.body.detalle||null,estado:"pendiente"}).select().single();
  let aviso="";
  if(eIns&&/prods/.test(eIns.message||"")){
    // la columna prods todavía no existe en la base: guardar sin el detalle y avisarlo
    const r2=await db.from("cargas").insert({conductor:cond,items,detalle:req.body.detalle||null,estado:"pendiente"}).select().single();
    nc=r2.data;eIns=r2.error;
    aviso="Falta ejecutar el SQL en Supabase (columna prods en cargas). La carga se guardó SIN el detalle por producto, así que el conductor no verá el stock producto por producto.";
  }
  if(eIns||!nc)return res.status(500).json({ok:false,error:"No se pudo guardar la carga: "+((eIns&&eIns.message)||"sin respuesta de la base")});
  // el viaje empieza aquí: se abre turno al conductor
  await db.from("conductores").update({en_turno:true,turno_hora:new Date().toISOString(),turno_ini:new Date().toISOString()}).eq("usuario",cond);
  await db.from("logs").insert({tipo:"turno",detalle:cond+" inicia (carga asignada)"});
  await avisoA(cond,"📦 Tienes una carga asignada: "+Object.keys(items).map(k=>k+" "+items[k]).join(", ")+". Confírmala antes de salir.");
  res.json({ok:true,id:nc.id,aviso:aviso||undefined,con_detalle:!!prods&&!aviso});
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
  const campos={nombre:60,zona:40,tipo:20,dueno:60,tel:15,notas:200,hora_ini:5,hora_fin:5,dias_no:30};
  const upd={},cambios=[];
  Object.keys(campos).forEach(k=>{
    if(req.body[k]==null)return;
    const v=(k==="tel")?String(req.body[k]).replace(/\D/g,"").slice(0,15):limpia(req.body[k],campos[k]);
    if(String(ant[k]||"")!==String(v||"")){upd[k]=v;cambios.push(k+': "'+(ant[k]||"—")+'" → "'+(v||"—")+'"');}
  });
  ["lat","lon"].forEach(k=>{ if(req.body[k]!=null){const v=num(req.body[k],k==="lat"?-90:-180,k==="lat"?90:180);
    if(Number(ant[k])!==v){upd[k]=v;cambios.push(k+": "+(ant[k]??"—")+" → "+v);} }});
  if(req.body.vip!=null&&!!ant.vip!==!!req.body.vip){upd.vip=!!req.body.vip;cambios.push("VIP: "+(req.body.vip?"sí":"no"));}
  if(req.body.act!=null&&!!ant.act!==!!req.body.act){upd.act=!!req.body.act;cambios.push("Activa: "+(req.body.act?"sí":"no"));}
  if(!cambios.length)return res.json({ok:true,sin_cambios:true});
  await db.from("tiendas").update(upd).eq("id",req.params.id);
  await db.from("logs").insert({tipo:"tienda",detalle:"#"+req.params.id+" "+(ant.nombre||"")+" · "+cambios.join(" · ")});
  res.json({ok:true,cambios:cambios.length});
});
app.get("/admin/tiendas/:id/historial",authA,async(req,res)=>{
  const{data}=await db.from("logs").select("*").eq("tipo","tienda").ilike("detalle","#"+req.params.id+" %").order("id",{ascending:false}).limit(40);
  res.json({ok:true,filas:data||[]});
});
app.post("/tiendas/:id/verificar",authA,async(req,res)=>{
  try{await db.from("eventos").update({visto:true}).eq("tipo","tienda_nueva").eq("ref",String(req.params.id));}catch(e){}await db.from("tiendas").update({verificada:true,nueva:false}).eq("id",req.params.id);res.json({ok:true});});
app.post("/tiendas/:id/credito",authA,async(req,res)=>{await db.from("tiendas").update({cr:!!req.body.habilitado,li:num(req.body.limite,0,100000)||230}).eq("id",req.params.id);
  await db.from("logs").insert({tipo:"admin",detalle:"Crédito tienda #"+req.params.id+" → S/"+num(req.body.limite,0,100000)});res.json({ok:true});});
app.post("/admin/tiendas",authA,async(req,res)=>{
  const b=req.body;
  if(!b.n)return res.status(400).json({ok:false,error:"Falta el nombre"});
  const fila={nombre:b.n,zona:b.z||"",tipo:b.tp||"bodega",dueno:b.d||"",tel:String(b.tel||"").replace(/\D/g,"").slice(0,15),notas:b.no||"",hora_ini:limpia(b.h_ini,5),hora_fin:limpia(b.h_fin,5),dias_no:limpia(b.dias_no,30),lat:(b.lat==null?null:num(b.lat,-90,90)),lon:(b.lon==null?null:num(b.lon,-180,180)),cr:!!b.cr,sa:0,li:Number(b.li)||0,vip:false,act:true,nueva:false,verificada:true,conductor_reg:"admin"};
  if(b.conductor){fila.conductor_asig=b.conductor;fila.asig_fecha=hoy();} // reservada: no vence
  const{data:t,error}=await db.from("tiendas").insert(fila).select().single();
  if(error)return res.status(500).json({ok:false,error:error.message});
  if(b.conductor)await avisoA(b.conductor,"🏪 Te asigné la tienda "+b.n+(b.z?" ("+b.z+")":"")+" — entra en tu ruta de HOY.");
  res.json({ok:true,id:t.id});
});
app.post("/admin/tiendas/:id/asignar",authA,async(req,res)=>{
  const{data:t}=await db.from("tiendas").select("nombre,zona").eq("id",req.params.id).maybeSingle();
  if(!t)return res.status(404).json({ok:false});
  await db.from("tiendas").update({conductor_asig:req.body.conductor||null,asig_fecha:req.body.conductor?hoy():null}).eq("id",req.params.id); // reservada hasta que el dueño la cambie
  if(req.body.conductor)await avisoA(req.body.conductor,"🏪 Te asigné la tienda "+t.nombre+(t.zona?" ("+t.zona+")":"")+" — entra en tu ruta de HOY.");
  res.json({ok:true});
});
app.post("/creditos",authA,async(req,res)=>{ // abonos del dueño (bloque 38)
  const{tienda_id,monto}=req.body;const{data:t}=await db.from("tiendas").select("sa").eq("id",tienda_id).single();
  await db.from("creditos_mov").insert({tienda_id,tipo:"pago",monto:num(monto,0,999999),detalle:"Abono registrado por el dueño",por:"admin"});
  await db.from("tiendas").update({sa:Math.max(0,Number(t.sa||0)-Number(monto||0))}).eq("id",tienda_id);
  res.json({ok:true});
});
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
  const filas=arr.map((x,i)=>({id:limpia(x.id,20).toLowerCase().replace(/[^a-z0-9_]/g,""),nom:limpia(x.nom,50),
    emoji:limpia(x.emoji,4)||"📦",precio:num(x.precio,0,10000),orden:i,activa:x.activa!==false})).filter(x=>x.id&&x.nom);
  if(!filas.length)return res.status(400).json({ok:false,error:"Sin categorías"});
  const{error}=await db.from("categorias").upsert(filas);
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
  let qv=db.from("ventas").select("items,total,creado,conductor").gte("creado",d+"T00:00:00").lte("creado",h+"T23:59:59");
  if(cond&&cond!=="todos")qv=qv.eq("conductor",cond);
  const [vts,prods,params]=await Promise.all([
    qv,
    db.from("catalogo").select("id,cat,nombre,costo"),
    getParams()
  ]).then(r=>[r[0].data||[],r[1].data||[],r[2]]);
  const costoProd={},catDe={},nomDe={};
  prods.forEach(p=>{costoProd[p.id]=Number(p.costo||0);catDe[p.id]=p.cat;nomDe[p.id]=p.nombre;});
  const costoCat=params.costos||{};
  let venta=0,costo=0,sinCosto=0;
  const porCat={};
  vts.forEach(v=>{
    (Array.isArray(v.items)?v.items:[]).forEach(it=>{
      if(!it||!it.id)return;
      const q=num(it.c,0,9999),pu=num(it.pu,0,10000);
      const cat=catDe[it.id]||"—";
      const cu=costoProd[it.id]>0?costoProd[it.id]:num(costoCat[cat],0,10000);
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
  const rango=q=>{if(desde)q=q.gte("creado",desde+"T00:00:00");if(hasta)q=q.lte("creado",hasta+"T23:59:59");return q;};
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
  const{data:cgs}=await db.from("cargas").select("id,conductor,estado,items,creado").order("id",{ascending:false}).limit(20);
  res.json({ok:true,conteos:out,ultimas_tiendas:ult||[],ultimos_pedidos:pds||[],ultimas_cargas:cgs||[],gps_error:GPS_ULTIMO_ERROR||null});
});
app.post("/almacen",authC,async(req,res)=>{
  const items=catsOK(req.body.items);
  if(!items)return res.status(400).json({ok:false,error:"Sin productos"});
  const tipo=(req.body.tipo==="salida")?"salida":"retorno";
  await db.from("kardex").insert({conductor:req.cond.u,tipo:"almacen_"+tipo,detalle:JSON.stringify(items)+(req.body.nota?" · "+limpia(req.body.nota,120):"")});
  await evento("almacen","🏬 "+(tipo==="retorno"?"Sobrante al almacén":"Salida de almacén")+" — "+req.cond.u,
    Object.keys(items).map(k=>k+" "+items[k]).join(", "),"");
  res.json({ok:true});
});
app.post("/admin/almacen/enviar",authA,async(req,res)=>{
  const para=String(req.body.conductor||"");
  const prodsA=limpiaProds(req.body.prods||req.body.items);
  if(!Object.keys(prodsA).length||!USR_RE.test(para))return res.status(400).json({ok:false,error:"Faltan datos"});
  const items=await porCategoria(prodsA);
  const{data:t}=await db.from("traspasos").insert({de:"almacen",de_nombre:"Almacén",para,prods:prodsA,items,conf_de:true,estado:"parcial"}).select().single();
  await avisoA(para,"🏬 El almacén te envía: "+Object.keys(items).map(k=>k+" "+items[k]).join(", ")+". Confírmalo al recibirlo.");
  res.json({ok:true,id:t.id});
});
app.post("/admin/almacen/pedir",authA,async(req,res)=>{
  const de=String(req.body.conductor||"");
  const prodsR=limpiaProds(req.body.prods||req.body.items);
  if(!Object.keys(prodsR).length||!USR_RE.test(de))return res.status(400).json({ok:false,error:"Faltan datos"});
  const items=await porCategoria(prodsR);
  const{data:t}=await db.from("traspasos").insert({de,de_nombre:de,para:"almacen",prods:prodsR,items,conf_para:true,estado:"parcial"}).select().single();
  await avisoA(de,"🏬 Debes entregar al almacén: "+Object.keys(items).map(k=>k+" "+items[k]).join(", ")+". Confirma cuando lo dejes.");
  res.json({ok:true,id:t.id});
});
app.get("/admin/creditos",authA,async(req,res)=>{
  const{data:mov}=await db.from("creditos_mov").select("*").order("id",{ascending:false}).limit(200);
  const{data:tds}=await db.from("tiendas").select("id,nombre,sa,li,cr");
  const map={};(tds||[]).forEach(t=>map[t.id]=t.nombre);
  res.json({ok:true,
    movimientos:(mov||[]).map(m=>({...m,tienda:map[m.tienda_id]||("#"+m.tienda_id)})),
    saldos:(tds||[]).filter(t=>Number(t.sa||0)>0).sort((a,b)=>Number(b.sa)-Number(a.sa)),
    total:(tds||[]).reduce((s,t)=>s+Number(t.sa||0),0)});
});
app.post("/admin/creditos/abono",authA,async(req,res)=>{
  const id=req.body.tienda_id, monto=num(req.body.monto,0.1,999999);
  if(!id||!monto)return res.status(400).json({ok:false,error:"Falta tienda o monto"});
  const{data:t}=await db.from("tiendas").select("nombre,sa").eq("id",id).maybeSingle();
  if(!t)return res.status(404).json({ok:false,error:"Tienda no encontrada"});
  await db.from("creditos_mov").insert({tienda_id:id,tipo:"abono",monto,detalle:limpia(req.body.detalle,120)||"Abono registrado por el dueño",por:"admin"});
  await db.from("tiendas").update({sa:Math.max(0,Number(t.sa||0)-monto)}).eq("id",id);
  await db.from("logs").insert({tipo:"admin",detalle:"Abono S/"+monto.toFixed(2)+" de "+t.nombre});
  res.json({ok:true,nuevo_saldo:Math.max(0,Number(t.sa||0)-monto)});
});
app.get("/admin/almacen",authA,async(req,res)=>{
  const{data}=await db.from("kardex").select("*").like("tipo","almacen_%").order("id",{ascending:false}).limit(300);
  const stock={};
  (data||[]).forEach(k=>{
    let it={};try{it=JSON.parse(String(k.detalle).split(" · ")[0])}catch(e){}
    const signo=(k.tipo==="almacen_retorno")?1:-1;
    Object.keys(it).forEach(cat=>{stock[cat]=(stock[cat]||0)+signo*Number(it[cat]||0)});
  });
  res.json({ok:true,stock,movimientos:(data||[]).slice(0,60)});
});
app.post("/admin/almacen/ajuste",authA,async(req,res)=>{
  const items=catsOK(req.body.items);
  if(!items)return res.status(400).json({ok:false,error:"Sin productos"});
  const tipo=(req.body.tipo==="salida")?"salida":"retorno";
  await db.from("kardex").insert({conductor:"admin",tipo:"almacen_"+tipo,detalle:JSON.stringify(items)+" · ajuste del dueño"+(req.body.nota?": "+limpia(req.body.nota,120):"")});
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
    qk=qk.gte("creado",d+"T00:00:00").lte("creado",h+"T23:59:59").limit(800);
    qv=qv.gte("creado",d+"T00:00:00").lte("creado",h+"T23:59:59").limit(800);
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
    .gte("creado",d+"T00:00:00").lte("creado",d+"T23:59:59").order("creado").limit(2000);
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
    const HORAS=num(process.env.ALERTA_QUIETO_H,1,12)||3;
    const desde=new Date(Date.now()-HORAS*3600000).toISOString();
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
        lista+": "+HORAS+" h en el mismo lugar y sin registrar ventas. Puede ser avería, bloqueo de vía o un problema.","");
      avisarAdmin("🛑 "+HORAS+" h detenido(s) y sin ventas: "+lista);
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
    if(frias.length)await evento("inactivas","😴 "+frias.length+" tienda(s) sin comprar hace "+D+"+ días",frias.map(t=>t.nombre).join(", ")+". Revisa si conviene visitarlas o si dejaron de trabajar contigo.","");
  }catch(e){console.error("cron inactivas:",e.message);}
},{timezone:"America/Lima"});

// ════════ INFORME DIARIO 22:00 (hora Perú) ════════
cron.schedule("0 22 * * *",async()=>{
  try{
    const{data:vs}=await db.from("ventas").select("*").gte("creado",hoy()+"T00:00:00");
    const tot=(vs||[]).reduce((s,v)=>s+Number(v.total||0),0);
    const por={};(vs||[]).forEach(v=>{por[v.conductor]=(por[v.conductor]||0)+Number(v.total||0)});
    let analisis="";
    if(anthropic){try{const r=await anthropic.messages.create({model:MODELO_IA,max_tokens:300,system:"Eres analista de una distribuidora de panes en Perú. Un párrafo ejecutivo en español, máx 80 palabras: lo importante del día, alertas y qué mirar mañana.",messages:[{role:"user",content:JSON.stringify({fecha:hoy(),total:tot,porConductor:por,ventas:(vs||[]).length})}]});analisis="\n\nANÁLISIS\n"+r.content[0].text;}catch(e){console.log("IA informe:",e.message);}}
    await avisarAdmin("📊 INFORME "+hoy()+"\nVentas: S/"+tot.toFixed(2)+" ("+(vs||[]).length+" entregas)\n"+Object.entries(por).map(([k,v])=>k+": S/"+v.toFixed(2)).join("\n")+analisis);
  }catch(e){console.error("Informe:",e.message);}
},{timezone:"America/Lima"});
// Limpieza de logs a 30 días
cron.schedule("0 3 * * *",async()=>{const lim=new Date(Date.now()-30*86400000).toISOString();await db.from("logs").delete().lt("creado",lim).neq("tipo","admin");},{timezone:"America/Lima"});

const PORT=process.env.PORT||3000;
app.listen(PORT,()=>console.log("Servidor v5.0 en puerto "+PORT+" · IA solo informes · Twilio solo alertas al dueño"));
