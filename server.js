const fs=require('fs'),path=require('path'),crypto=require('crypto'),os=require('os'),express=require('express');
const app=express();app.use(express.static(path.join(__dirname,'public')));
const sec=!process.env.PORT&&fs.existsSync('key.pem'); // hosting platforms set PORT and provide HTTPS themselves
const srv=sec?require('https').createServer({key:fs.readFileSync('key.pem'),cert:fs.readFileSync('cert.pem')},app):require('http').createServer(app);
const io=require('socket.io')(srv,{maxHttpBufferSize:5e7});
const F='data.json';let D={S:{u:{},s:[],m:{},t:{},vc:{},vs:{},g:{}},C:{}};
try{D=JSON.parse(fs.readFileSync(F))}catch(e){}
let tm;const save=()=>{clearTimeout(tm);tm=setTimeout(()=>fs.writeFile(F,JSON.stringify(D),()=>{}),500)};
const hash=(p,s)=>crypto.scryptSync(p,s,32).toString('hex');
io.on('connection',so=>{
 so.emit('state',D.S);
 so.on('auth',({u,p,reg},cb)=>{u=String(u||'');p=String(p||'');
  if(reg){if(!/^\w{2,20}$/.test(u))return cb({e:'Username: 2-20 letters/numbers'});if(p.length<3)return cb({e:'Password too short'});if(D.C[u])return cb({e:'Username taken'});
   const s=crypto.randomBytes(8).toString('hex');D.C[u]={s,h:hash(p,s)};D.S.u[u]={st:'online',cs:'',g:'',f:[]}}
  else{const c=D.C[u];if(!c||c.h!==hash(p,c.s))return cb({e:'Invalid username or password'})}
  so.user=u;save();cb({ok:1,s:D.S})});
 so.on('state',s=>{if(!so.user||!s||typeof s!='object')return;for(const k in (s.u||{}))if(!D.C[k])delete s.u[k];D.S=s;so.broadcast.emit('state',s);save()});
 so.on('join',k=>{const ids=[...(io.sockets.adapter.rooms.get(k)||[])];so.k=k;so.join(k);so.emit('peers',ids);if(k[0]=='d'||k[0]=='g')so.broadcast.emit('ring',{k,u:so.user})});
 so.on('sig',({to,d})=>io.to(to).emit('sig',{from:so.id,d}));
 const out=()=>{if(so.k){so.to(so.k).emit('gone',so.id);so.leave(so.k);so.k=null}};
 so.on('leave',out);
 so.on('disconnect',()=>{out();if(so.user){for(const k in D.S.vc)D.S.vc[k]=D.S.vc[k].filter(x=>x!=so.user);io.emit('state',D.S);save()}});
});
const P=process.env.PORT||3000;
srv.listen(P,'0.0.0.0',()=>{const pr=sec?'https':'http';console.log('nexxx running:\n  '+pr+'://localhost:'+P);Object.values(os.networkInterfaces()).flat().filter(i=>i.family=='IPv4'&&!i.internal).forEach(i=>console.log('  '+pr+'://'+i.address+':'+P+'  (phone, same Wi-Fi)'))});
