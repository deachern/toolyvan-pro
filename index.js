'use strict';
const express=require('express');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const {v4:uuidv4}=require('uuid');
const https=require('https');
const cors=require('cors');
const fs=require('fs');
require('dotenv').config();

// ── CONSTANTS ─────────────────────────────────────────────────
const JWT_SECRET=process.env.JWT_SECRET||'toolyvans2024dev';
const PAYSTACK_SECRET=process.env.PAYSTACK_SECRET_KEY||'';
const ADMIN_EMAIL=process.env.ADMIN_EMAIL||'admin@toolyvans.com';
const ADMIN_PASS=process.env.ADMIN_PASSWORD||'Admin@2024!';
const SS_PRICE=3, RG_PRICE=2, CR_PRICE=2;
const REFERRAL_BONUS=5; // $5 per successful referral

// ── DATABASE ──────────────────────────────────────────────────
const DB_PATH='/tmp/tv_db.json';
function readDB(){
  try{if(fs.existsSync(DB_PATH))return JSON.parse(fs.readFileSync(DB_PATH,'utf8'));}catch(_){}
  return{users:[],transactions:[],sites:[],receipts:[],cryptoRecs:[],referrals:[]};
}
function writeDB(db){try{fs.writeFileSync(DB_PATH,JSON.stringify(db));}catch(e){console.error(e.message);}}

// ── PAYSTACK ──────────────────────────────────────────────────
function psReq(method,path,body){
  return new Promise((res,rej)=>{
    const payload=body?JSON.stringify(body):'';
    const req=https.request({hostname:'api.paystack.co',path,method,
      headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(payload),'Authorization':`Bearer ${PAYSTACK_SECRET}`}
    },r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>{try{res({s:r.statusCode,d:JSON.parse(d)});}catch(e){rej(e);}});});
    req.on('error',rej);if(payload)req.write(payload);req.end();
  });
}

// ── EXPRESS ───────────────────────────────────────────────────
const app=express();
app.use(cors({origin:'*',methods:['GET','POST','OPTIONS']}));
app.use(express.json({limit:'2mb'}));
app.use(express.urlencoded({extended:true}));

// ── AUTH MIDDLEWARE ───────────────────────────────────────────
function auth(req,res,next){
  const raw=req.headers.authorization||'';
  const token=raw.startsWith('Bearer ')?raw.slice(7):raw;
  if(!token)return res.status(401).json({error:'Unauthorized'});
  try{req.user=jwt.verify(token,JWT_SECRET);next();}
  catch(_){res.status(401).json({error:'Invalid or expired token'});}
}
function adminAuth(req,res,next){
  auth(req,res,()=>{if(!req.user.isAdmin)return res.status(403).json({error:'Admin only'});next();});
}

// ═══════════════ AUTH ═══════════════════════════════════════
app.post('/api/auth/register',async(req,res)=>{
  try{
    const{name,email,password,referralCode}=req.body||{};
    if(!name?.trim()||!email?.trim()||!password)return res.status(400).json({error:'All fields required'});
    if(password.length<6)return res.status(400).json({error:'Password min 6 characters'});
    const db=readDB(),low=email.toLowerCase().trim();
    if(db.users.find(u=>u.email===low))return res.status(400).json({error:'Email already registered'});
    const myCode='TV'+Math.random().toString(36).slice(2,8).toUpperCase();
    const user={id:uuidv4(),name:name.trim(),email:low,password:await bcrypt.hash(password,12),
      balance:0,createdAt:new Date().toISOString(),referralCode:myCode,referredBy:null,isAdmin:false};
    // Process referral
    if(referralCode){
      const ref=db.users.find(u=>u.referralCode===referralCode.toUpperCase());
      if(ref){
        user.referredBy=ref.id;
        ref.balance=+(ref.balance+REFERRAL_BONUS).toFixed(2);
        db.transactions.push({id:uuidv4(),userId:ref.id,type:'referral',description:'Referral Bonus — '+name,amount:REFERRAL_BONUS,reference:'REF-'+user.id.slice(0,8),status:'success',icon:'group_add',createdAt:new Date().toISOString()});
        if(!db.referrals)db.referrals=[];
        db.referrals.push({id:uuidv4(),referrerId:ref.id,referredId:user.id,referredName:name,bonus:REFERRAL_BONUS,createdAt:new Date().toISOString()});
      }
    }
    db.users.push(user);writeDB(db);
    const token=jwt.sign({id:user.id,email:user.email,isAdmin:false},JWT_SECRET,{expiresIn:'14d'});
    res.status(201).json({token,user:{id:user.id,name:user.name,email:user.email,balance:user.balance,referralCode:myCode}});
  }catch(e){console.error(e);res.status(500).json({error:'Registration failed'});}
});

app.post('/api/auth/login',async(req,res)=>{
  try{
    const{email,password}=req.body||{};
    if(!email||!password)return res.status(400).json({error:'Email and password required'});
    // Admin login
    if(email.toLowerCase()===ADMIN_EMAIL.toLowerCase()&&password===ADMIN_PASS){
      const token=jwt.sign({id:'admin',email:ADMIN_EMAIL,isAdmin:true},JWT_SECRET,{expiresIn:'14d'});
      return res.json({token,user:{id:'admin',name:'Admin',email:ADMIN_EMAIL,balance:0,isAdmin:true}});
    }
    const db=readDB(),user=db.users.find(u=>u.email===email.toLowerCase().trim());
    if(!user||!(await bcrypt.compare(password,user.password)))return res.status(401).json({error:'Invalid email or password'});
    const token=jwt.sign({id:user.id,email:user.email,isAdmin:false},JWT_SECRET,{expiresIn:'14d'});
    res.json({token,user:{id:user.id,name:user.name,email:user.email,balance:user.balance,referralCode:user.referralCode,isAdmin:false}});
  }catch(e){console.error(e);res.status(500).json({error:'Login failed'});}
});

app.get('/api/auth/me',auth,(req,res)=>{
  if(req.user.isAdmin)return res.json({id:'admin',name:'Admin',email:ADMIN_EMAIL,balance:0,isAdmin:true});
  const db=readDB(),user=db.users.find(u=>u.id===req.user.id);
  if(!user)return res.status(404).json({error:'User not found'});
  res.json({id:user.id,name:user.name,email:user.email,balance:user.balance,referralCode:user.referralCode,isAdmin:false});
});

// ═══════════════ DASHBOARD ═══════════════════════════════════
app.get('/api/dashboard',auth,(req,res)=>{
  const db=readDB(),user=db.users.find(u=>u.id===req.user.id);
  if(!user)return res.status(404).json({error:'User not found'});
  const txs=db.transactions.filter(t=>t.userId===req.user.id).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).slice(0,50);
  const sites=db.sites.filter(s=>s.userId===req.user.id);
  const recs=(db.receipts||[]).filter(r=>r.userId===req.user.id);
  const crecs=(db.cryptoRecs||[]).filter(r=>r.userId===req.user.id);
  const refs=(db.referrals||[]).filter(r=>r.referrerId===req.user.id);
  const spent=txs.filter(t=>t.amount<0).reduce((s,t)=>s+Math.abs(t.amount),0);
  res.json({balance:user.balance,transactions:txs,referralCode:user.referralCode,stats:{sites:sites.length,receipts:recs.length+crecs.length,totalSpent:+spent.toFixed(2),referrals:refs.length,referralEarnings:refs.length*REFERRAL_BONUS}});
});

// ═══════════════ REFERRAL ════════════════════════════════════
app.get('/api/referrals',auth,(req,res)=>{
  const db=readDB();
  const refs=(db.referrals||[]).filter(r=>r.referrerId===req.user.id).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt));
  res.json({referrals:refs,bonus:REFERRAL_BONUS});
});

// ═══════════════ PAYSTACK ════════════════════════════════════
app.post('/api/payment/initialize',auth,async(req,res)=>{
  try{
    const amount=parseFloat(req.body?.amount);
    if(!amount||amount<5)return res.status(400).json({error:'Minimum deposit is $5'});
    const db=readDB(),user=db.users.find(u=>u.id===req.user.id);
    if(!user)return res.status(404).json({error:'User not found'});
    const r=await psReq('POST','/transaction/initialize',{email:user.email,amount:Math.round(amount*100),currency:'NGN',reference:'TV-'+Date.now()+'-'+uuidv4().split('-')[0],callback_url:process.env.APP_URL||'https://toolyvans.vercel.app',metadata:{userId:user.id,depositAmountUSD:amount}});
    if(!r.d?.data)return res.status(500).json({error:r.d?.message||'Paystack init failed'});
    res.json({authorizationUrl:r.d.data.authorization_url,reference:r.d.data.reference});
  }catch(e){console.error(e);res.status(500).json({error:'Payment init failed'});}
});

app.post('/api/payment/verify',auth,async(req,res)=>{
  try{
    const{reference}=req.body||{};
    if(!reference)return res.status(400).json({error:'Reference required'});
    const db=readDB(),user=db.users.find(u=>u.id===req.user.id);
    if(!user)return res.status(404).json({error:'User not found'});
    const dup=db.transactions.find(t=>t.reference===reference&&t.type==='deposit');
    if(dup)return res.json({success:true,balance:user.balance,amount:dup.amount,alreadyProcessed:true});
    const r=await psReq('GET',`/transaction/verify/${reference}`,null);
    const pd=r.d?.data;
    if(!pd||pd.status!=='success')return res.status(400).json({error:`Payment not confirmed (${pd?.status||'unknown'})`});
    const amt=+(pd.amount/100).toFixed(2);
    user.balance=+(user.balance+amt).toFixed(2);
    const tx={id:uuidv4(),userId:user.id,type:'deposit',description:'Paystack Deposit',amount:amt,reference,status:'success',icon:'add_task',createdAt:new Date().toISOString()};
    db.transactions.push(tx);writeDB(db);
    res.json({success:true,balance:user.balance,amount:amt,transaction:tx});
  }catch(e){console.error(e);res.status(500).json({error:'Verification failed'});}
});

// ═══════════════ TOOL 1 — SUPPORT SITE ═══════════════════════
app.post('/api/tools/support-site/generate',auth,async(req,res)=>{
  try{
    const{platform,contactMethod,contactValue,chatbotCode,days}=req.body||{};
    if(!platform)return res.status(400).json({error:'Platform required'});
    if(!contactMethod)return res.status(400).json({error:'Contact method required'});
    if(contactMethod!=='chatbot'&&!contactValue?.trim())return res.status(400).json({error:'Contact value required'});
    if(contactMethod==='chatbot'&&!chatbotCode?.trim())return res.status(400).json({error:'Chatbot code required'});
    const d=parseInt(days,10);
    if(!d||d<1||d>30)return res.status(400).json({error:'Duration 1-30 days'});
    const db=readDB(),user=db.users.find(u=>u.id===req.user.id);
    if(!user)return res.status(404).json({error:'User not found'});
    const cost=+(d*SS_PRICE).toFixed(2);
    if(user.balance<cost)return res.status(400).json({error:`Insufficient balance. Need $${cost}, have $${user.balance.toFixed(2)}`});
    user.balance=+(user.balance-cost).toFixed(2);
    const id=uuidv4().replace(/-/g,'').slice(0,10),plt=platform.toLowerCase();
    const slug=`${plt}-support-${id}`;
    const site={id,userId:user.id,type:'support-site',platform:plt,contactMethod,contactValue:contactValue?.trim()||'',chatbotCode:chatbotCode?.trim()||'',days:d,totalCost:cost,slug,expiresAt:new Date(Date.now()+d*86400000).toISOString(),createdAt:new Date().toISOString(),active:true};
    if(!db.sites)db.sites=[];
    db.sites.push(site);
    db.transactions.push({id:uuidv4(),userId:user.id,type:'billing',description:`Support Site — ${plt} (${d}d)`,amount:-cost,reference:`SITE-${id}`,status:'success',icon:'support_agent',createdAt:new Date().toISOString()});
    writeDB(db);
    res.json({success:true,siteId:id,slug,viewUrl:`/view/${slug}`,expiresAt:site.expiresAt,newBalance:user.balance,cost});
  }catch(e){console.error(e);res.status(500).json({error:'Generation failed'});}
});

app.get('/api/tools/support-site/list',auth,(req,res)=>{
  const db=readDB();
  res.json({sites:(db.sites||[]).filter(s=>s.userId===req.user.id).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))});
});

// ═══════════════ TOOL 2 — TRADING RECEIPT ════════════════════
app.post('/api/tools/receipt/generate',auth,async(req,res)=>{
  try{
    const{platform,tradeType,asset,amount,price,totalValue,date,txId,walletAddress,fee,days}=req.body||{};
    if(!platform)return res.status(400).json({error:'Platform required'});
    if(!asset?.trim())return res.status(400).json({error:'Asset required'});
    if(!amount||isNaN(+amount))return res.status(400).json({error:'Valid amount required'});
    if(!price||isNaN(+price))return res.status(400).json({error:'Valid price required'});
    if(!date)return res.status(400).json({error:'Trade date required'});
    if(!txId?.trim())return res.status(400).json({error:'Transaction ID required'});
    const d=parseInt(days,10);
    if(!d||d<1||d>30)return res.status(400).json({error:'Duration 1-30 days'});
    const db=readDB(),user=db.users.find(u=>u.id===req.user.id);
    if(!user)return res.status(404).json({error:'User not found'});
    const cost=+(d*RG_PRICE).toFixed(2);
    if(user.balance<cost)return res.status(400).json({error:`Insufficient balance. Need $${cost}, have $${user.balance.toFixed(2)}`});
    user.balance=+(user.balance-cost).toFixed(2);
    const id=uuidv4().replace(/-/g,'').slice(0,10),plt=platform.toLowerCase();
    const slug=`${plt}-receipt-${id}`;
    const receipt={id,userId:user.id,type:'receipt',platform:plt,tradeType:(tradeType||'BUY').toUpperCase(),asset:asset.trim().toUpperCase(),amount:+(+amount).toFixed(8),price:+(+price).toFixed(2),totalValue:+(totalValue||(+amount*+price)).toFixed(2),date,txId:txId.trim(),walletAddress:walletAddress?.trim()||'',fee:+(+(fee||0)).toFixed(2),days:d,totalCost:cost,slug,expiresAt:new Date(Date.now()+d*86400000).toISOString(),createdAt:new Date().toISOString(),active:true};
    if(!db.receipts)db.receipts=[];
    db.receipts.push(receipt);
    db.transactions.push({id:uuidv4(),userId:user.id,type:'billing',description:`Receipt — ${plt} ${receipt.tradeType} ${receipt.asset} (${d}d)`,amount:-cost,reference:`RCPT-${id}`,status:'success',icon:'receipt_long',createdAt:new Date().toISOString()});
    writeDB(db);
    res.json({success:true,receiptId:id,slug,viewUrl:`/view/${slug}`,expiresAt:receipt.expiresAt,newBalance:user.balance,cost});
  }catch(e){console.error(e);res.status(500).json({error:'Generation failed'});}
});

app.get('/api/tools/receipt/list',auth,(req,res)=>{
  const db=readDB();
  res.json({receipts:(db.receipts||[]).filter(r=>r.userId===req.user.id).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))});
});

// ═══════════════ TOOL 3 — CRYPTO RECEIPT ═════════════════════
app.post('/api/tools/crypto-receipt/generate',auth,async(req,res)=>{
  try{
    const{brand,receiptType,coin,network,amount,address,txid,status,dateTime,days}=req.body||{};
    if(!brand)return res.status(400).json({error:'Brand required'});
    if(!amount)return res.status(400).json({error:'Amount required'});
    if(!address?.trim())return res.status(400).json({error:'Address required'});
    const d=parseInt(days,10);
    if(!d||d<1||d>30)return res.status(400).json({error:'Duration 1-30 days'});
    const db=readDB(),user=db.users.find(u=>u.id===req.user.id);
    if(!user)return res.status(404).json({error:'User not found'});
    const cost=+(d*CR_PRICE).toFixed(2);
    if(user.balance<cost)return res.status(400).json({error:`Insufficient balance. Need $${cost}, have $${user.balance.toFixed(2)}`});
    user.balance=+(user.balance-cost).toFixed(2);
    const id=uuidv4().replace(/-/g,'').slice(0,10);
    const slug=`crypto-${brand.toLowerCase().replace(/\s+/g,'-')}-${id}`;
    if(!db.cryptoRecs)db.cryptoRecs=[];
    const rec={id,userId:user.id,type:'crypto-receipt',brand,receiptType:receiptType||'crypto',coin:coin||'USDT',network:network||'TRC20',amount,address:address.trim(),txid:txid?.trim()||'',status:status||'completed',dateTime,days:d,totalCost:cost,slug,expiresAt:new Date(Date.now()+d*86400000).toISOString(),createdAt:new Date().toISOString()};
    db.cryptoRecs.push(rec);
    db.transactions.push({id:uuidv4(),userId:user.id,type:'billing',description:`Crypto Receipt — ${brand} (${d}d)`,amount:-cost,reference:`CREC-${id}`,status:'success',icon:'receipt',createdAt:new Date().toISOString()});
    writeDB(db);
    res.json({success:true,receiptId:id,slug,viewUrl:`/view/${slug}`,expiresAt:rec.expiresAt,newBalance:user.balance,cost});
  }catch(e){console.error(e);res.status(500).json({error:'Generation failed'});}
});

app.get('/api/tools/crypto-receipt/list',auth,(req,res)=>{
  const db=readDB();
  res.json({receipts:(db.cryptoRecs||[]).filter(r=>r.userId===req.user.id).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))});
});

// ═══════════════ PUBLIC VIEW ═════════════════════════════════
app.get('/api/view/:slug',(req,res)=>{
  const db=readDB(),{slug}=req.params;
  const site=(db.sites||[]).find(s=>s.slug===slug);
  if(site){
    if(new Date()>new Date(site.expiresAt))return res.status(410).json({error:'expired',message:'This support site has expired.'});
    const{userId:_,...pub}=site;return res.json({type:'support-site',data:pub});
  }
  const receipt=(db.receipts||[]).find(r=>r.slug===slug);
  if(receipt){
    if(new Date()>new Date(receipt.expiresAt))return res.status(410).json({error:'expired',message:'This receipt has expired.'});
    const{userId:_,...pub}=receipt;return res.json({type:'receipt',data:pub});
  }
  const crec=(db.cryptoRecs||[]).find(r=>r.slug===slug);
  if(crec){
    if(new Date()>new Date(crec.expiresAt))return res.status(410).json({error:'expired',message:'This receipt has expired.'});
    const{userId:_,...pub}=crec;return res.json({type:'crypto-receipt',data:pub});
  }
  res.status(404).json({error:'not_found',message:'Link not found.'});
});

// ═══════════════ ADMIN ═══════════════════════════════════════
app.get('/api/admin/stats',adminAuth,(req,res)=>{
  const db=readDB();
  const revenue=db.transactions.filter(t=>t.type==='deposit').reduce((s,t)=>s+t.amount,0);
  const toolRevenue=db.transactions.filter(t=>t.type==='billing').reduce((s,t)=>s+Math.abs(t.amount),0);
  res.json({
    users:db.users.length,
    sites:(db.sites||[]).length,
    receipts:((db.receipts||[]).length+(db.cryptoRecs||[]).length),
    referrals:(db.referrals||[]).length,
    totalDeposits:+revenue.toFixed(2),
    toolRevenue:+toolRevenue.toFixed(2),
    recentUsers:db.users.slice(-10).reverse().map(u=>({id:u.id,name:u.name,email:u.email,balance:u.balance,createdAt:u.createdAt})),
    recentTx:db.transactions.slice(-20).reverse()
  });
});

app.get('/api/admin/users',adminAuth,(req,res)=>{
  const db=readDB();
  res.json({users:db.users.map(u=>({id:u.id,name:u.name,email:u.email,balance:u.balance,createdAt:u.createdAt,referralCode:u.referralCode}))});
});

app.post('/api/admin/credit',adminAuth,(req,res)=>{
  const{userId,amount,note}=req.body||{};
  if(!userId||!amount)return res.status(400).json({error:'userId and amount required'});
  const db=readDB(),user=db.users.find(u=>u.id===userId);
  if(!user)return res.status(404).json({error:'User not found'});
  user.balance=+(user.balance+parseFloat(amount)).toFixed(2);
  db.transactions.push({id:uuidv4(),userId,type:'admin_credit',description:note||'Admin Credit',amount:parseFloat(amount),reference:'ADM-'+uuidv4().slice(0,8),status:'success',icon:'admin_panel_settings',createdAt:new Date().toISOString()});
  writeDB(db);
  res.json({success:true,newBalance:user.balance});
});

// ═══════════════ HTML PAGES ══════════════════════════════════

// Logo SVG inline (Toolyvans gear logo black/yellow theme)
const LOGO_SVG=`<svg width="36" height="36" viewBox="0 0 36 36" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="18" cy="18" r="18" fill="#1a1a1a"/><path d="M18 8a10 10 0 1 0 0 20A10 10 0 0 0 18 8zm0 15a5 5 0 1 1 0-10 5 5 0 0 1 0 10z" fill="#F5C518"/><path d="M16 2h4v4h-4zM16 30h4v4h-4zM2 16h4v4H2zM30 16h4v4h-4zM5.5 5.5l2.8 2.8-2.8 2.8L2.7 8.3zM27.7 27.7l2.8 2.8-2.8 2.8-2.8-2.8zM5.5 30.5l2.8-2.8 2.8 2.8-2.8 2.8zM27.7 8.3l2.8-2.8 2.8 2.8-2.8 2.8z" fill="#F5C518"/></svg>`;

const CSS_COMMON=`
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --black:#0a0a0a;--dark:#111111;--dark2:#1a1a1a;--dark3:#222222;--dark4:#2a2a2a;
  --yellow:#F5C518;--yellow2:#e6b800;--yellow-dim:rgba(245,197,24,0.12);--yellow-glow:rgba(245,197,24,0.25);
  --white:#ffffff;--gray:#888;--gray2:#555;--gray3:#333;
  --green:#22c55e;--red:#ef4444;--blue:#3b82f6;
  --surface:rgba(255,255,255,0.04);--surface2:rgba(255,255,255,0.07);--surface3:rgba(255,255,255,0.10);
  --border:rgba(255,255,255,0.08);--border2:rgba(255,255,255,0.12);--border-yellow:rgba(245,197,24,0.3);
  --radius:10px;--radius-lg:16px;--radius-xl:22px;--radius-full:9999px;
  --font:'Geist',sans-serif;--font-mono:'IBM Plex Mono',monospace;
  --shadow:0 8px 32px rgba(0,0,0,0.6);--shadow-y:0 4px 20px rgba(245,197,24,0.2);
  --glass:rgba(255,255,255,0.04);--glass-border:rgba(255,255,255,0.08);
}
html,body{background:var(--black);color:var(--white);font-family:var(--font);font-size:14px;line-height:1.6;min-height:100vh}
/* GLASS */
.glass{background:var(--glass);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);border:1px solid var(--glass-border);border-radius:var(--radius-lg)}
.glass-yellow{background:var(--yellow-dim);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--border-yellow);border-radius:var(--radius-lg)}
/* LOADER */
.loader{display:flex;align-items:center}
.bar{display:inline-block;width:3px;height:20px;background:rgba(245,197,24,.5);border-radius:10px;animation:su 1s linear infinite}
.bar:nth-child(2){height:35px;margin:0 5px;animation-delay:.25s}.bar:nth-child(3){animation-delay:.5s}
@keyframes su{20%{background:var(--yellow);transform:scaleY(1.5)}40%{transform:scaleY(1)}}
/* BUTTON */
.btn{cursor:pointer;border-radius:14px;border:none;padding:2px;background:linear-gradient(135deg,#F5C518,#c9a000);position:relative;font-family:var(--font);display:inline-block}
.btn::after{content:"";position:absolute;width:65%;height:55%;border-radius:100px;top:0;right:0;box-shadow:0 0 18px rgba(245,197,24,0.4);z-index:-1}
.blob{position:absolute;width:60px;height:100%;border-radius:14px;bottom:0;left:0;background:radial-gradient(circle 50px at 0% 100%,rgba(245,197,24,0.6),rgba(180,140,0,0.4),transparent);box-shadow:-8px 8px 24px rgba(245,197,24,0.15)}
.inn{padding:11px 22px;border-radius:12px;color:var(--black);z-index:3;position:relative;background:linear-gradient(135deg,#F5C518 0%,#d4a800 100%);font-weight:700;font-size:14px;display:flex;align-items:center;justify-content:center;gap:7px;letter-spacing:.01em}
.inn::before{content:"";width:100%;height:100%;left:0;top:0;border-radius:12px;background:linear-gradient(180deg,rgba(255,255,255,0.15),transparent);position:absolute;pointer-events:none}
.btn:disabled .inn{opacity:.5}.btn:disabled{cursor:not-allowed}
.btn-sm{cursor:pointer;border-radius:10px;border:none;padding:1.5px;background:linear-gradient(135deg,#F5C518,#c9a000);position:relative;font-family:var(--font);display:inline-block}
.btn-sm .inn{padding:7px 14px;border-radius:8px;font-size:12px;font-weight:700;gap:5px}
.btn-out{background:transparent;border:1px solid var(--border2);color:var(--white);border-radius:var(--radius);padding:9px 18px;cursor:pointer;font-size:13px;font-family:var(--font);font-weight:500;transition:.2s;display:flex;align-items:center;gap:6px}
.btn-out:hover{border-color:var(--yellow);color:var(--yellow)}
.btn-ghost{background:var(--surface);border:1px solid var(--border);color:var(--gray);border-radius:var(--radius);padding:8px 16px;cursor:pointer;font-size:12px;font-family:var(--font);transition:.2s;display:flex;align-items:center;gap:5px}
.btn-ghost:hover{color:var(--white);border-color:var(--border2)}
/* FORM */
.fg{margin-bottom:14px}
.fl{display:block;font-size:11px;font-weight:600;color:var(--gray);margin-bottom:5px;text-transform:uppercase;letter-spacing:.05em}
.fi{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:11px 14px;color:var(--white);font-size:14px;font-family:var(--font);outline:none;transition:.2s}
.fi:focus{border-color:var(--yellow);box-shadow:0 0 0 3px var(--yellow-dim)}
.fi::placeholder{color:var(--gray2)}
.sel{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:11px 14px;color:var(--white);font-size:14px;font-family:var(--font);outline:none;appearance:none;cursor:pointer}
.sel:focus{border-color:var(--yellow)}
.sel-wrap{position:relative}.sel-arr{position:absolute;right:10px;top:50%;transform:translateY(-50%);color:var(--gray);pointer-events:none;font-size:17px}
/* TOAST */
#toast{position:fixed;bottom:22px;right:22px;background:var(--dark3);border:1px solid var(--border2);border-radius:var(--radius-lg);padding:12px 16px;font-size:13px;color:var(--white);z-index:9999;display:flex;align-items:center;gap:8px;transform:translateY(80px);opacity:0;transition:.3s;max-width:300px;box-shadow:var(--shadow)}
#toast.show{transform:translateY(0);opacity:1}
#toast.success .tic{color:var(--green)}#toast.error .tic{color:var(--red)}#toast.warn .tic{color:var(--yellow)}
/* GRID */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
/* BADGE */
.bdg{padding:2px 8px;border-radius:var(--radius-full);font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em}
.bdg-y{background:var(--yellow-dim);color:var(--yellow);border:1px solid var(--border-yellow)}
.bdg-g{background:rgba(34,197,94,.1);color:var(--green);border:1px solid rgba(34,197,94,.2)}
.bdg-r{background:rgba(239,68,68,.1);color:var(--red);border:1px solid rgba(239,68,68,.15)}
.bdg-b{background:rgba(59,130,246,.1);color:var(--blue);border:1px solid rgba(59,130,246,.15)}
/* PLATFORM LOGOS — using official CDN favicons */
.plt-logo{width:32px;height:32px;border-radius:50%;object-fit:contain;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0}
.plt-logo-wrap{width:32px;height:32px;border-radius:50%;overflow:hidden;background:#fff;display:flex;align-items:center;justify-content:center;flex-shrink:0;border:2px solid var(--border)}
.plt-logo-wrap img{width:22px;height:22px;object-fit:contain}
/* SLIDER */
.sdr-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.sdr-val{background:var(--yellow);color:var(--black);padding:2px 10px;border-radius:var(--radius-full);font-size:12px;font-weight:700}
.rng{width:100%;height:4px;cursor:pointer;accent-color:var(--yellow)}
.sdr-lbl{display:flex;justify-content:space-between;margin-top:5px;font-size:10px;color:var(--gray)}
/* COST BOX */
.cost-box{background:var(--yellow-dim);border:1px solid var(--border-yellow);border-radius:var(--radius-lg);padding:14px 16px;margin:16px 0;display:flex;align-items:center;justify-content:space-between}
.cost-big{font-size:1.4rem;font-weight:800;color:var(--yellow)}
/* TABLE */
.tbl{width:100%;border-collapse:collapse}
.tbl th{padding:9px 14px;text-align:left;font-size:10px;font-weight:700;color:var(--gray);text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--border)}
.tbl th:last-child{text-align:right}.tbl td:last-child{text-align:right}
.tbl td{padding:11px 14px;border-bottom:1px solid rgba(255,255,255,.04);font-size:13px;color:var(--white)}
.tbl tr:hover td{background:rgba(255,255,255,.02)}
.tbl tr:last-child td{border-bottom:none}
/* GEN ITEM */
.gen-item{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:12px 14px;margin-bottom:8px;display:flex;align-items:center;justify-content:space-between;gap:12px}
.gen-nm{font-size:13px;font-weight:600;color:var(--white)}
.gen-mt{font-size:11px;color:var(--gray);margin-top:2px}
.gen-acts{display:flex;gap:7px;flex-shrink:0}
.cpbtn{padding:5px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;font-size:11px;color:var(--gray);cursor:pointer;transition:.2s;display:flex;align-items:center;gap:3px;font-family:var(--font)}
.cpbtn:hover{border-color:var(--yellow);color:var(--yellow)}
.vwbtn{padding:5px 10px;background:var(--yellow-dim);border:1px solid var(--border-yellow);border-radius:8px;font-size:11px;color:var(--yellow);cursor:pointer;transition:.2s;display:flex;align-items:center;gap:3px;font-family:var(--font);font-weight:600;text-decoration:none}
.vwbtn:hover{background:rgba(245,197,24,.2)}
/* PLATFORM GRID */
.pgrid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-top:4px}
.popt{border:1px solid var(--border);border-radius:var(--radius-lg);padding:10px 6px;text-align:center;cursor:pointer;transition:.2s;background:var(--surface);display:flex;flex-direction:column;align-items:center;gap:6px}
.popt:hover{border-color:var(--yellow-2,#e6b800)}.popt.on{border-color:var(--yellow);background:var(--yellow-dim)}
.popt .pn{font-size:10px;font-weight:600;color:var(--gray)}.popt.on .pn{color:var(--yellow)}
/* BRAND GRID */
.bgrid{display:grid;grid-template-columns:repeat(6,1fr);gap:7px;margin-top:4px}
.bopt{border:1px solid var(--border);border-radius:var(--radius-lg);padding:8px 4px;text-align:center;cursor:pointer;transition:.2s;background:var(--surface);display:flex;flex-direction:column;align-items:center;gap:4px}
.bopt:hover{border-color:var(--yellow)}.bopt.on{border-color:var(--yellow);background:var(--yellow-dim)}
.bopt img{width:20px;height:20px;object-fit:contain;border-radius:4px}
.bopt .bn{font-size:9px;font-weight:600;color:var(--gray)}.bopt.on .bn{color:var(--yellow)}
/* STATUS GRID */
.sgrid{display:grid;grid-template-columns:repeat(3,1fr);gap:7px}
.sopt{border:1px solid var(--border);border-radius:var(--radius);padding:8px;text-align:center;cursor:pointer;transition:.2s;background:var(--surface);font-size:11px;font-weight:600;color:var(--gray)}
.sopt:hover{border-color:var(--yellow)}.sopt.on{border-color:var(--yellow);background:var(--yellow-dim);color:var(--yellow)}
/* CONTACT GRID */
.cgrid{display:grid;grid-template-columns:repeat(4,1fr);gap:7px}
.copt{border:1px solid var(--border);border-radius:var(--radius-lg);padding:10px 6px;text-align:center;cursor:pointer;transition:.2s;background:var(--surface);display:flex;flex-direction:column;align-items:center;gap:5px}
.copt:hover{border-color:var(--yellow)}.copt.on{border-color:var(--yellow);background:var(--yellow-dim)}
.copt .ms{font-size:18px;color:var(--gray)}.copt.on .ms{color:var(--yellow)}
.copt .cl{font-size:10px;font-weight:600;color:var(--gray)}.copt.on .cl{color:var(--yellow)}
/* DEPOSIT CHIPS */
.dchips{display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin-bottom:14px}
.dchip{padding:11px;text-align:center;border-radius:var(--radius-lg);background:var(--surface);border:1px solid var(--border);cursor:pointer;transition:.2s;font-weight:700;font-size:14px;color:var(--white)}
.dchip:hover{border-color:var(--yellow)}.dchip.on{background:var(--yellow-dim);border-color:var(--yellow);color:var(--yellow)}
/* REFERRAL */
.ref-box{background:var(--yellow-dim);border:1px solid var(--border-yellow);border-radius:var(--radius-lg);padding:16px;display:flex;align-items:center;gap:10px;margin-bottom:16px}
.ref-code{font-family:var(--font-mono);font-size:1rem;font-weight:700;color:var(--yellow);letter-spacing:.1em}
/* STAT CARDS */
.stat{padding:18px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-xl);position:relative;overflow:hidden;transition:.2s}
.stat::before{content:'';position:absolute;top:-50%;right:-20%;width:100px;height:100px;border-radius:50%;opacity:.06}
.stat.y::before{background:var(--yellow)}.stat.g::before{background:var(--green)}.stat.b::before{background:var(--blue)}.stat.r::before{background:var(--red)}
.stat-ic{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;margin-bottom:10px}
.stat-ic.y{background:var(--yellow-dim);color:var(--yellow)}.stat-ic.g{background:rgba(34,197,94,.12);color:var(--green)}.stat-ic.b{background:rgba(59,130,246,.12);color:var(--blue)}.stat-ic.r{background:rgba(239,68,68,.12);color:var(--red)}
.stat-lbl{font-size:10px;font-weight:600;color:var(--gray);text-transform:uppercase;letter-spacing:.06em;margin-bottom:5px}
.stat-val{font-size:1.5rem;font-weight:800;color:var(--white);line-height:1}
/* PANEL FORM CARD */
.fcard{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-xl);overflow:hidden;max-width:700px}
.fcard-hdr{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.back-btn{width:28px;height:28px;border-radius:8px;background:var(--surface2);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--gray);transition:.2s;flex-shrink:0}
.back-btn:hover{color:var(--yellow);border-color:var(--yellow)}.back-btn .ms{font-size:17px}
.fcard-body{padding:20px}
/* CHART */
.chart-bars{display:flex;align-items:flex-end;gap:6px;height:100px}
.cb-w{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px}
.cb{width:100%;border-radius:4px 4px 0 0;background:rgba(245,197,24,.2);min-height:4px;transition:.2s;cursor:pointer}
.cb:hover{background:rgba(245,197,24,.45)}.cb.now{background:var(--yellow);box-shadow:0 -4px 12px rgba(245,197,24,.4)}
.cd{font-size:9px;color:var(--gray);font-weight:600;text-transform:uppercase}
/* RESPONSIVE */
@media(max-width:900px){.pgrid{grid-template-columns:repeat(3,1fr)}.bgrid{grid-template-columns:repeat(3,1fr)}}
@media(max-width:600px){.g2,.g3,.g4{grid-template-columns:1fr}.pgrid{grid-template-columns:repeat(3,1fr)}}
`;

// Platform logos using official favicons + inline SVG fallbacks
const PLAT_LOGOS={
  binance:{url:'https://bin.bnbstatic.com/static/images/common/favicon.ico',bg:'#181A20',fallback:'🟡'},
  bybit:{url:'https://www.bybit.com/favicon.ico',bg:'#1C1C1E',fallback:'🟠'},
  coinbase:{url:'https://www.coinbase.com/favicon.ico',bg:'#0052FF',fallback:'🔵'},
  metamask:{url:'https://raw.githubusercontent.com/MetaMask/brand-resources/master/SVG/SVG_MetaMask_Icon_Color.svg',bg:'#F6851B',fallback:'🦊'},
  trustwallet:{url:'https://trustwallet.com/assets/images/media/assets/TWT.png',bg:'#3375BB',fallback:'🔷'},
  robinhood:{url:'https://robinhood.com/favicon.ico',bg:'#00C805',fallback:'🟢'},
  phantom:{url:'https://phantom.app/img/phantom-logo.png',bg:'#9945FF',fallback:'👻'},
  kraken:{url:'https://www.kraken.com/favicon.ico',bg:'#5741D9',fallback:'🐙'},
  kucoin:{url:'https://www.kucoin.com/favicon.ico',bg:'#23AF91',fallback:'🐢'},
  okx:{url:'https://static.okx.com/cdn/assets/imgs/221/9E073F600D8C8D77.png',bg:'#000000',fallback:'⚫'}
};

function pltLogoHTML(k,size=32){
  const p=PLAT_LOGOS[k];
  if(!p)return `<div style="width:${size}px;height:${size}px;border-radius:50%;background:var(--surface2);display:flex;align-items:center;justify-content:center;font-size:${size*0.5}px">🌐</div>`;
  return `<div style="width:${size}px;height:${size}px;border-radius:50%;background:${p.bg};overflow:hidden;display:flex;align-items:center;justify-content:center;border:2px solid rgba(255,255,255,0.1);flex-shrink:0"><img src="${p.url}" width="${size*0.65}" height="${size*0.65}" style="object-fit:contain" onerror="this.parentElement.innerHTML='<span style=font-size:${size*0.45}px>${p.fallback}</span>'"/></div>`;
}

const DASHBOARD_HTML=`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Toolyvans — Fintech Tools Platform</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700;800;900&family=Inter:wght@300;400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
<script src="https://js.paystack.co/v1/inline.js"><\/script>
<style>
${CSS_COMMON}
html,body{overflow:hidden;height:100%}
/* ── APP LOADER ── */
#ldr{position:fixed;inset:0;background:var(--black);display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:9999;gap:24px;transition:opacity .5s,visibility .5s}
#ldr.gone{opacity:0;visibility:hidden;pointer-events:none}
.ldr-logo{display:flex;align-items:center;gap:12px}
.ldr-logo img{width:48px;height:48px;border-radius:50%}
.ldr-name{font-size:1.6rem;font-weight:900;letter-spacing:-.04em;color:var(--white)}
.ldr-name span{color:var(--yellow)}
/* ── LAYOUT ── */
#app{display:flex;height:100vh;overflow:hidden}
.pg{display:none;width:100%;height:100%}.pg.active{display:flex}
/* ── LANDING ── */
#land-pg{flex-direction:column;overflow-y:auto;background:var(--black)}
/* HERO */
.land-nav{height:64px;display:flex;align-items:center;justify-content:space-between;padding:0 40px;position:sticky;top:0;z-index:100;background:rgba(10,10,10,0.85);backdrop-filter:blur(20px);border-bottom:1px solid var(--border)}
.land-nav-brand{display:flex;align-items:center;gap:10px}
.land-nav-brand img{width:36px;height:36px;border-radius:50%}
.land-nav-name{font-size:1rem;font-weight:800;letter-spacing:-.03em;color:var(--white)}
.land-nav-name span{color:var(--yellow)}
.land-nav-links{display:flex;align-items:center;gap:8px}
.land-nav-link{padding:7px 14px;border-radius:8px;font-size:13px;font-weight:500;color:var(--gray);cursor:pointer;transition:.2s;background:none;border:none;font-family:var(--font)}
.land-nav-link:hover{color:var(--white)}
.hero{padding:100px 40px 80px;text-align:center;position:relative;overflow:hidden}
.hero::before{content:'';position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:600px;height:600px;border-radius:50%;background:radial-gradient(circle,rgba(245,197,24,0.08) 0%,transparent 70%);pointer-events:none}
.hero-badge{display:inline-flex;align-items:center;gap:6px;background:var(--yellow-dim);border:1px solid var(--border-yellow);border-radius:var(--radius-full);padding:4px 14px;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--yellow);margin-bottom:24px}
.hero-badge-dot{width:5px;height:5px;border-radius:50%;background:var(--yellow);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.hero-h1{font-size:clamp(2.4rem,6vw,4rem);font-weight:900;letter-spacing:-.04em;line-height:1.05;margin-bottom:20px;color:var(--white)}
.hero-h1 span{color:var(--yellow)}
.hero-sub{font-size:1.05rem;color:var(--gray);max-width:560px;margin:0 auto 36px;line-height:1.7}
.hero-acts{display:flex;justify-content:center;gap:12px;flex-wrap:wrap}
/* TOOLS SECTION */
.land-sec{padding:64px 40px;max-width:1200px;margin:0 auto;width:100%}
.land-sec-hdr{text-align:center;margin-bottom:48px}
.land-sec-badge{display:inline-flex;align-items:center;gap:5px;background:var(--yellow-dim);border:1px solid var(--border-yellow);border-radius:var(--radius-full);padding:3px 12px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--yellow);margin-bottom:12px}
.land-sec-h{font-size:clamp(1.6rem,4vw,2.4rem);font-weight:900;letter-spacing:-.04em;color:var(--white);margin-bottom:10px}
.land-sec-sub{color:var(--gray);font-size:.95rem;max-width:520px;margin:0 auto}
.tools-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}
.tool-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-xl);padding:28px;transition:.3s;cursor:pointer;position:relative;overflow:hidden}
.tool-card::before{content:'';position:absolute;top:-60px;right:-40px;width:140px;height:140px;border-radius:50%;opacity:.06;transition:.3s}
.tool-card.y::before{background:var(--yellow)}.tool-card.g::before{background:var(--green)}.tool-card.b::before{background:var(--blue)}
.tool-card:hover{border-color:var(--yellow);transform:translateY(-4px);box-shadow:var(--shadow-y)}
.tool-card:hover::before{opacity:.12}
.tool-card-ic{width:52px;height:52px;border-radius:14px;display:flex;align-items:center;justify-content:center;margin-bottom:18px}
.tool-card-ic.y{background:var(--yellow-dim)}.tool-card-ic.g{background:rgba(34,197,94,.12)}.tool-card-ic.b{background:rgba(59,130,246,.12)}
.tool-card-name{font-size:1.05rem;font-weight:800;letter-spacing:-.02em;color:var(--white);margin-bottom:8px}
.tool-card-desc{font-size:13px;color:var(--gray);line-height:1.7;margin-bottom:16px}
.tool-card-price{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--gray)}
.tool-card-price strong{font-size:1rem;font-weight:800;color:var(--yellow)}
/* HOW IT WORKS */
.steps-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:20px}
.step-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-xl);padding:24px;text-align:center;position:relative}
.step-num{width:40px;height:40px;border-radius:50%;background:var(--yellow-dim);border:2px solid var(--border-yellow);display:flex;align-items:center;justify-content:center;font-weight:900;font-size:1rem;color:var(--yellow);margin:0 auto 14px}
.step-title{font-weight:700;font-size:.95rem;color:var(--white);margin-bottom:6px}
.step-desc{font-size:12px;color:var(--gray);line-height:1.6}
/* FAQ */
.faq-wrap{max-width:700px;margin:0 auto;display:flex;flex-direction:column;gap:8px}
.faq-item{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);overflow:hidden;transition:.2s}
.faq-item:hover{border-color:var(--yellow)}
.faq-q{padding:16px 18px;display:flex;align-items:center;justify-content:space-between;cursor:pointer;font-weight:600;font-size:14px;color:var(--white);gap:12px}
.faq-ch{font-size:18px;color:var(--gray);transition:.2s;flex-shrink:0}
.faq-a{padding:0 18px;max-height:0;overflow:hidden;transition:.3s;font-size:13px;color:var(--gray);line-height:1.7}
.faq-item.open .faq-a{max-height:200px;padding:0 18px 16px}.faq-item.open .faq-ch{transform:rotate(180deg);color:var(--yellow)}
/* PLATFORMS STRIP */
.plat-strip{display:flex;gap:16px;justify-content:center;flex-wrap:wrap;padding:40px;background:var(--surface);border-top:1px solid var(--border);border-bottom:1px solid var(--border)}
.plat-item{display:flex;align-items:center;gap:8px;padding:8px 16px;border-radius:var(--radius-full);background:var(--surface2);border:1px solid var(--border)}
.plat-item-name{font-size:12px;font-weight:600;color:var(--gray)}
/* REFERRAL SECTION */
.ref-hero{background:var(--yellow-dim);border:1px solid var(--border-yellow);border-radius:var(--radius-xl);padding:40px;text-align:center}
.ref-hero-h{font-size:1.8rem;font-weight:900;letter-spacing:-.03em;color:var(--white);margin-bottom:10px}
.ref-hero-h span{color:var(--yellow)}
.ref-hero-sub{color:var(--gray);margin-bottom:24px}
/* FOOTER */
.land-footer{background:var(--dark);border-top:1px solid var(--border);padding:32px 40px;text-align:center}
.land-footer-brand{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:12px}
.land-footer-brand img{width:30px;height:30px;border-radius:50%}
.land-footer-name{font-weight:800;font-size:.95rem;color:var(--white)}
.land-footer-name span{color:var(--yellow)}
.land-footer-copy{font-size:12px;color:var(--gray)}
/* ── AUTH ── */
#auth-pg{align-items:center;justify-content:center;background:var(--black);background-image:radial-gradient(ellipse at 20% 50%,rgba(245,197,24,0.06) 0%,transparent 50%)}
.acard{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-xl);padding:36px;width:100%;max-width:420px;box-shadow:var(--shadow)}
.alogo{display:flex;align-items:center;gap:10px;margin-bottom:26px}
.alogo img{width:38px;height:38px;border-radius:50%}
.alogo-name{font-weight:800;font-size:1rem;color:var(--white)}
.alogo-name span{color:var(--yellow)}
.alogo-sub{font-size:11px;color:var(--gray)}
.atabs{display:flex;background:var(--surface2);border-radius:var(--radius);padding:4px;margin-bottom:22px}
.atab{flex:1;padding:8px;border-radius:8px;border:none;background:transparent;color:var(--gray);font-size:13px;font-weight:600;cursor:pointer;transition:.2s;font-family:var(--font)}
.atab.on{background:var(--yellow);color:var(--black)}
.ferr{color:var(--red);font-size:12px;margin-top:4px;display:none}
.ref-input-wrap{display:flex;gap:8px;align-items:center;margin-top:8px}
.ref-badge-small{background:var(--yellow-dim);border:1px solid var(--border-yellow);border-radius:8px;padding:8px 12px;font-size:11px;color:var(--yellow);font-weight:600;white-space:nowrap}
/* ── DASHBOARD ── */
#dash-pg{flex-direction:row}
.sidebar{width:260px;min-width:260px;background:var(--dark);border-right:1px solid var(--border);display:flex;flex-direction:column;height:100vh}
.sb-hdr{padding:16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.sb-hdr img{width:34px;height:34px;border-radius:50%}
.sb-name{font-weight:800;font-size:.9rem;color:var(--white)}
.sb-name span{color:var(--yellow)}
.sb-tag{font-size:10px;color:var(--gray)}
.sb-nav{flex:1;padding:12px 10px;display:flex;flex-direction:column;gap:2px;overflow-y:auto}
.nav-sec{font-size:10px;font-weight:700;color:var(--gray2);letter-spacing:.08em;text-transform:uppercase;padding:10px 10px 4px}
.ni{display:flex;align-items:center;gap:9px;padding:9px 10px;border-radius:var(--radius);cursor:pointer;transition:.2s;color:var(--gray);border:none;background:transparent;font-family:var(--font);font-size:13px;font-weight:500;width:100%;text-align:left}
.ni:hover{background:var(--surface2);color:var(--white)}
.ni.on{background:var(--yellow-dim);color:var(--yellow);border-left:3px solid var(--yellow);padding-left:7px}
.ni .ms{font-size:17px;flex-shrink:0}.ni.on .ms{font-variation-settings:'FILL' 1}
.sb-ft{padding:12px 10px;border-top:1px solid var(--border)}
.ucard{display:flex;align-items:center;gap:10px;padding:10px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-lg);margin-bottom:8px}
.uavt{width:32px;height:32px;border-radius:50%;background:var(--yellow);display:flex;align-items:center;justify-content:center;color:var(--black);font-weight:800;font-size:13px;flex-shrink:0}
.uname{font-size:12px;font-weight:600;color:var(--white)}
.ubal{font-size:11px;color:var(--yellow);font-weight:600}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;background:var(--black)}
.topbar{height:56px;border-bottom:1px solid var(--border);padding:0 22px;display:flex;align-items:center;justify-content:space-between;background:rgba(10,10,10,0.85);backdrop-filter:blur(20px);flex-shrink:0}
.topbar-title{font-weight:800;font-size:.9rem;letter-spacing:-.02em;color:var(--white)}
.ib{width:34px;height:34px;border-radius:var(--radius);background:var(--surface);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--gray);transition:.2s}
.ib:hover{border-color:var(--yellow);color:var(--yellow)}.ib .ms{font-size:17px}
.scroll{flex:1;overflow-y:auto;padding:20px 22px}
.scroll::-webkit-scrollbar{width:4px}.scroll::-webkit-scrollbar-thumb{background:var(--gray2);border-radius:4px}
.panel{display:none}.panel.on{display:block;animation:fi .2s ease}
@keyframes fi{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.ph{margin-bottom:18px}
.ph h1{font-size:1.4rem;font-weight:900;letter-spacing:-.03em;color:var(--white);margin-bottom:3px}
.ph p{color:var(--gray);font-size:13px}
.bal-card{padding:22px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-xl);position:relative;overflow:hidden}
.bal-card::after{content:'';position:absolute;top:-60px;right:-60px;width:160px;height:160px;border-radius:50%;background:rgba(245,197,24,0.06);pointer-events:none}
.bal-lbl{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--gray);margin-bottom:6px}
.bal-amt{font-size:2rem;font-weight:900;letter-spacing:-.04em;color:var(--white);margin-bottom:4px}
.bal-grow{display:flex;align-items:center;gap:5px;color:var(--yellow);font-size:12px;font-weight:600;margin-bottom:18px}
.bal-acts{display:flex;gap:10px;flex-wrap:wrap}
/* ADMIN */
.admin-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
@media(max-width:1100px){.tools-grid{grid-template-columns:repeat(2,1fr)}.steps-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:700px){.tools-grid{grid-template-columns:1fr}.steps-grid{grid-template-columns:1fr}.land-nav{padding:0 16px}.hero{padding:60px 20px 50px}.land-sec{padding:40px 20px}.sidebar{display:none}.scroll{padding:14px}}
</style>
</head>
<body>

<!-- LOADER -->
<div id="ldr">
  <div class="ldr-logo">
    <img src="https://i.imgur.com/placeholder.png" id="ldr-img" alt="Toolyvans" onerror="this.style.display='none'"/>
    <div class="ldr-name">Tooly<span>vans</span></div>
  </div>
  <div class="loader"><div class="bar"></div><div class="bar"></div><div class="bar"></div></div>
</div>
<div id="toast"><div class="tic"><span class="ms material-symbols-outlined">check_circle</span></div><span id="tmsg">Done!</span></div>

<div id="app">

<!-- ═══════════════ LANDING PAGE ═══════════════ -->
<div id="land-pg" class="pg">
  <nav class="land-nav">
    <div class="land-nav-brand">
      <div style="width:36px;height:36px;border-radius:50%;background:var(--yellow);display:flex;align-items:center;justify-content:center;font-weight:900;font-size:16px;color:var(--black)">T</div>
      <div class="land-nav-name">Tooly<span>vans</span></div>
    </div>
    <div class="land-nav-links">
      <button class="land-nav-link" onclick="scrollTo('tools-sec')">Tools</button>
      <button class="land-nav-link" onclick="scrollTo('how-sec')">How It Works</button>
      <button class="land-nav-link" onclick="scrollTo('faq-sec')">FAQ</button>
      <button class="btn-out" style="margin-left:8px" onclick="showAuth()">Sign In</button>
      <button class="btn" onclick="showAuth('register')" style="margin-left:4px"><div class="inn" style="padding:8px 18px;font-size:13px">Get Started</div></button>
    </div>
  </nav>

  <!-- HERO -->
  <div class="hero">
    <div class="hero-badge"><span class="hero-badge-dot"></span>Professional Fintech Tools</div>
    <h1 class="hero-h1">Generate Branded<br/><span>Fintech Assets</span><br/>Instantly</h1>
    <p class="hero-sub">Create professional support sites, trading receipts and crypto receipts for any platform. Pay per day, share your link, done.</p>
    <div class="hero-acts">
      <button class="btn" onclick="showAuth('register')"><div class="blob"></div><div class="inn"><span class="material-symbols-outlined ms" style="font-size:16px">rocket_launch</span>Start for Free</div></button>
      <button class="btn-out" onclick="scrollTo('tools-sec')"><span class="material-symbols-outlined ms" style="font-size:16px">explore</span>Explore Tools</button>
    </div>
  </div>

  <!-- PLATFORMS STRIP -->
  <div class="plat-strip" id="plat-strip-land"></div>

  <!-- TOOLS -->
  <div class="land-sec" id="tools-sec">
    <div class="land-sec-hdr">
      <div class="land-sec-badge"><span class="material-symbols-outlined ms" style="font-size:13px">precision_manufacturing</span>Our Tools</div>
      <h2 class="land-sec-h">Everything You Need</h2>
      <p class="land-sec-sub">Three professional tools. Pay per day. Cancel anytime. Share instantly.</p>
    </div>
    <div class="tools-grid">
      <div class="tool-card y" onclick="showAuth('register')">
        <div class="tool-card-ic y"><span class="material-symbols-outlined ms" style="font-size:26px;color:var(--yellow)">support_agent</span></div>
        <div class="tool-card-name">Support Site Generator</div>
        <div class="tool-card-desc">Create fully branded trading-platform support microsites with floating contact buttons, custom themes, FAQ sections and shareable URLs.</div>
        <div class="tool-card-price"><strong>$3</strong>/day &nbsp;·&nbsp; Binance, Bybit, Coinbase +7 more</div>
        <div style="margin-top:14px"><span class="bdg bdg-y">Live Link</span> &nbsp;<span class="bdg bdg-g">1–30 Days</span> &nbsp;<span class="bdg bdg-b">Custom Theme</span></div>
      </div>
      <div class="tool-card g" onclick="showAuth('register')">
        <div class="tool-card-ic g"><span class="material-symbols-outlined ms" style="font-size:26px;color:var(--green)">receipt_long</span></div>
        <div class="tool-card-name">Trading Receipt Generator</div>
        <div class="tool-card-desc">Generate fully-branded trade receipts for any exchange. Buy, Sell, Deposit, Withdrawal — with platform logo, colors and shareable receipt links.</div>
        <div class="tool-card-price"><strong>$2</strong>/day &nbsp;·&nbsp; All major exchanges</div>
        <div style="margin-top:14px"><span class="bdg bdg-y">Live Link</span> &nbsp;<span class="bdg bdg-g">1–30 Days</span> &nbsp;<span class="bdg bdg-b">Platform Branded</span></div>
      </div>
      <div class="tool-card b" onclick="showAuth('register')">
        <div class="tool-card-ic b"><span class="material-symbols-outlined ms" style="font-size:26px;color:var(--blue)">receipt</span></div>
        <div class="tool-card-name">Crypto Receipt Generator</div>
        <div class="tool-card-desc">Styled crypto transaction receipts for Binance, Coinbase, OKX, Cash App, PayPal, Zelle and more. Completed, Pending or Canceled status.</div>
        <div class="tool-card-price"><strong>$2</strong>/day &nbsp;·&nbsp; 12 brands supported</div>
        <div style="margin-top:14px"><span class="bdg bdg-y">Live Link</span> &nbsp;<span class="bdg bdg-g">1–30 Days</span> &nbsp;<span class="bdg bdg-b">12 Brands</span></div>
      </div>
    </div>
  </div>

  <!-- HOW IT WORKS -->
  <div style="background:var(--dark);border-top:1px solid var(--border);border-bottom:1px solid var(--border)">
    <div class="land-sec" id="how-sec">
      <div class="land-sec-hdr">
        <div class="land-sec-badge"><span class="material-symbols-outlined ms" style="font-size:13px">map</span>How It Works</div>
        <h2 class="land-sec-h">Ready in Under 2 Minutes</h2>
        <p class="land-sec-sub">No technical skills required. Just fill in the details and get your link.</p>
      </div>
      <div class="steps-grid">
        <div class="step-card"><div class="step-num">1</div><div class="step-title">Create Account</div><div class="step-desc">Sign up free and fund your wallet using Paystack.</div></div>
        <div class="step-card"><div class="step-num">2</div><div class="step-title">Choose a Tool</div><div class="step-desc">Pick Support Site, Trading Receipt or Crypto Receipt.</div></div>
        <div class="step-card"><div class="step-num">3</div><div class="step-title">Configure & Generate</div><div class="step-desc">Select platform, fill in details, choose duration and generate.</div></div>
        <div class="step-card"><div class="step-num">4</div><div class="step-title">Share Your Link</div><div class="step-desc">Get a live branded URL. Share it anywhere. It works instantly.</div></div>
      </div>
    </div>
  </div>

  <!-- REFERRAL -->
  <div class="land-sec">
    <div class="ref-hero glass">
      <div style="font-size:40px;margin-bottom:12px">🎁</div>
      <h2 class="ref-hero-h">Earn <span>$${REFERRAL_BONUS}</span> Per Referral</h2>
      <p class="ref-hero-sub">Share your unique referral link. For every friend who signs up, you earn $${REFERRAL_BONUS} added directly to your wallet — no cap.</p>
      <button class="btn" onclick="showAuth('register')"><div class="blob"></div><div class="inn"><span class="material-symbols-outlined ms" style="font-size:16px">group_add</span>Start Referring</div></button>
    </div>
  </div>

  <!-- FAQ -->
  <div style="background:var(--dark);border-top:1px solid var(--border)">
    <div class="land-sec" id="faq-sec">
      <div class="land-sec-hdr">
        <div class="land-sec-badge"><span class="material-symbols-outlined ms" style="font-size:13px">quiz</span>FAQ</div>
        <h2 class="land-sec-h">Frequently Asked Questions</h2>
      </div>
      <div class="faq-wrap">
        <div class="faq-item"><div class="faq-q" onclick="togFaq(this)"><span>How do I fund my wallet?</span><span class="faq-ch material-symbols-outlined">expand_more</span></div><div class="faq-a">Click Deposit Funds in your dashboard. We accept payments via Paystack — cards, bank transfer and more. Your balance updates immediately after payment.</div></div>
        <div class="faq-item"><div class="faq-q" onclick="togFaq(this)"><span>What happens when my link expires?</span><span class="faq-ch material-symbols-outlined">expand_more</span></div><div class="faq-a">When your chosen duration ends, the link shows an expired page. You can generate a new one anytime from your dashboard as long as you have sufficient balance.</div></div>
        <div class="faq-item"><div class="faq-q" onclick="togFaq(this)"><span>Can I pick any trading platform?</span><span class="faq-ch material-symbols-outlined">expand_more</span></div><div class="faq-a">Yes. We support Binance, Bybit, Coinbase, MetaMask, Trust Wallet, Robinhood, Phantom, Kraken, KuCoin and OKX — with accurate branding for each.</div></div>
        <div class="faq-item"><div class="faq-q" onclick="togFaq(this)"><span>How does the referral system work?</span><span class="faq-ch material-symbols-outlined">expand_more</span></div><div class="faq-a">Every account gets a unique referral code. When someone signs up using your code, you receive $${REFERRAL_BONUS} added to your wallet instantly. There's no limit on referrals.</div></div>
        <div class="faq-item"><div class="faq-q" onclick="togFaq(this)"><span>Is my data secure?</span><span class="faq-ch material-symbols-outlined">expand_more</span></div><div class="faq-a">Yes. All passwords are hashed with bcrypt. Payments are handled by Paystack — we never store card details. Your generated links are accessible only via the unique URL.</div></div>
        <div class="faq-item"><div class="faq-q" onclick="togFaq(this)"><span>Can I get a refund?</span><span class="faq-ch material-symbols-outlined">expand_more</span></div><div class="faq-a">Balance is non-refundable once tools are generated. However unused balance remains in your wallet and can be used for future generations at any time.</div></div>
      </div>
    </div>
  </div>

  <footer class="land-footer">
    <div class="land-footer-brand">
      <div style="width:30px;height:30px;border-radius:50%;background:var(--yellow);display:flex;align-items:center;justify-content:center;font-weight:900;font-size:14px;color:var(--black)">T</div>
      <div class="land-footer-name">Tooly<span>vans</span></div>
    </div>
    <div class="land-footer-copy">© 2024 Toolyvans. Professional Fintech Tools Platform.</div>
  </footer>
</div>

<!-- ═══════════════ AUTH PAGE ═══════════════ -->
<div id="auth-pg" class="pg">
  <div class="acard">
    <div class="alogo">
      <div style="width:38px;height:38px;border-radius:50%;background:var(--yellow);display:flex;align-items:center;justify-content:center;font-weight:900;font-size:18px;color:var(--black)">T</div>
      <div><div class="alogo-name">Tooly<span>vans</span></div><div class="alogo-sub">Fintech Solutions</div></div>
    </div>
    <div class="atabs"><button class="atab on" onclick="switchTab('login')">Sign In</button><button class="atab" onclick="switchTab('register')">Create Account</button></div>
    <div id="lf">
      <div class="fg"><label class="fl">Email</label><input type="email" class="fi" id="le" placeholder="you@example.com"/></div>
      <div class="fg"><label class="fl">Password</label><input type="password" class="fi" id="lp" placeholder="••••••••"/><div class="ferr" id="lerr"></div></div>
      <button class="btn" onclick="doLogin()" id="lbtn" style="width:100%"><div class="blob"></div><div class="inn"><span class="material-symbols-outlined ms" style="font-size:15px">login</span>Sign In</div></button>
      <div style="text-align:center;margin-top:14px;font-size:12px;color:var(--gray)">Don't have an account? <a onclick="switchTab('register')" style="color:var(--yellow);cursor:pointer;font-weight:600">Create one</a></div>
      <div style="text-align:center;margin-top:6px;font-size:12px;color:var(--gray)"><a onclick="showLanding()" style="color:var(--gray);cursor:pointer">← Back to home</a></div>
    </div>
    <div id="rf" style="display:none">
      <div class="fg"><label class="fl">Full Name</label><input type="text" class="fi" id="rn" placeholder="Alex Johnson"/></div>
      <div class="fg"><label class="fl">Email</label><input type="email" class="fi" id="re" placeholder="you@example.com"/></div>
      <div class="fg"><label class="fl">Password</label><input type="password" class="fi" id="rp" placeholder="Min 6 characters"/></div>
      <div class="fg"><label class="fl">Referral Code (optional)</label><input type="text" class="fi" id="rref" placeholder="e.g. TVAB12" style="text-transform:uppercase"/></div>
      <div class="ferr" id="rerr"></div>
      <button class="btn" onclick="doReg()" id="rbtn" style="width:100%;margin-top:4px"><div class="blob"></div><div class="inn"><span class="material-symbols-outlined ms" style="font-size:15px">person_add</span>Create Account</div></button>
      <div style="text-align:center;margin-top:14px;font-size:12px;color:var(--gray)">Already have an account? <a onclick="switchTab('login')" style="color:var(--yellow);cursor:pointer;font-weight:600">Sign in</a></div>
      <div style="text-align:center;margin-top:6px;font-size:12px;color:var(--gray)"><a onclick="showLanding()" style="color:var(--gray);cursor:pointer">← Back to home</a></div>
    </div>
  </div>
</div>

<!-- ═══════════════ DASHBOARD ═══════════════ -->
<div id="dash-pg" class="pg">
  <aside class="sidebar">
    <div class="sb-hdr">
      <div style="width:34px;height:34px;border-radius:50%;background:var(--yellow);display:flex;align-items:center;justify-content:center;font-weight:900;font-size:15px;color:var(--black);flex-shrink:0">T</div>
      <div><div class="sb-name">Tooly<span>vans</span></div><div class="sb-tag">Fintech Platform</div></div>
    </div>
    <nav class="sb-nav">
      <div class="nav-sec">Main</div>
      <button class="ni on" data-p="home" onclick="showPanel('home')"><span class="ms material-symbols-outlined">dashboard</span>Dashboard</button>
      <button class="ni" data-p="wallet" onclick="showPanel('wallet')"><span class="ms material-symbols-outlined">account_balance_wallet</span>Wallet</button>
      <button class="ni" data-p="referrals" onclick="showPanel('referrals')"><span class="ms material-symbols-outlined">group_add</span>Referrals</button>
      <div class="nav-sec">Tools</div>
      <button class="ni" data-p="tools" onclick="showPanel('tools')"><span class="ms material-symbols-outlined">precision_manufacturing</span>All Tools</button>
      <button class="ni" data-p="ss" onclick="showPanel('ss')"><span class="ms material-symbols-outlined">support_agent</span>Support Sites</button>
      <button class="ni" data-p="rg" onclick="showPanel('rg')"><span class="ms material-symbols-outlined">receipt_long</span>Receipt Gen</button>
      <button class="ni" data-p="cr" onclick="showPanel('cr')"><span class="ms material-symbols-outlined">receipt</span>Crypto Receipt</button>
      <div class="nav-sec">Account</div>
      <button class="ni" data-p="deposit" onclick="showPanel('deposit')"><span class="ms material-symbols-outlined">add_card</span>Deposit Funds</button>
      <button class="ni" data-p="activity" onclick="showPanel('activity')"><span class="ms material-symbols-outlined">history</span>Activity</button>
      <div id="admin-nav-item" style="display:none">
        <div class="nav-sec">Admin</div>
        <button class="ni" data-p="admin" onclick="showPanel('admin')"><span class="ms material-symbols-outlined">admin_panel_settings</span>Admin Panel</button>
      </div>
    </nav>
    <div class="sb-ft">
      <div class="ucard"><div class="uavt" id="sbavt">A</div><div><div class="uname" id="sbname">Loading…</div><div class="ubal">$<span id="sbbal">0.00</span></div></div></div>
      <button class="btn-out" style="width:100%;justify-content:center" onclick="doLogout()"><span class="material-symbols-outlined ms" style="font-size:15px">logout</span>Sign Out</button>
    </div>
  </aside>

  <div class="main">
    <div class="topbar">
      <div class="topbar-title" id="tbtitle">Dashboard</div>
      <div style="display:flex;gap:8px">
        <div class="ib" onclick="showPanel('deposit')" title="Deposit"><span class="ms material-symbols-outlined">add_card</span></div>
        <div class="ib" onclick="showPanel('referrals')" title="Referrals"><span class="ms material-symbols-outlined">group_add</span></div>
      </div>
    </div>
    <div class="scroll">

      <!-- HOME -->
      <div class="panel on" id="panel-home">
        <div class="ph"><h1>Good morning, <span id="wname">there</span> 👋</h1><p>Your Toolyvans dashboard overview.</p></div>
        <div class="g2" style="margin-bottom:14px">
          <div class="bal-card glass">
            <div class="bal-lbl">Available Balance</div>
            <div class="bal-amt">$<span id="hbal">0.00</span></div>
            <div class="bal-grow"><span class="material-symbols-outlined ms" style="font-size:15px">trending_up</span>Live wallet balance</div>
            <div class="bal-acts">
              <button class="btn-sm" onclick="showPanel('deposit')"><div class="blob"></div><div class="inn"><span class="material-symbols-outlined ms" style="font-size:13px">add_circle</span>Deposit</div></button>
              <button class="btn-out" onclick="showPanel('activity')"><span class="material-symbols-outlined ms" style="font-size:15px">history</span>History</button>
            </div>
          </div>
          <div class="glass" style="padding:18px">
            <div style="font-weight:800;font-size:.9rem;color:var(--white);margin-bottom:12px;letter-spacing:-.01em">Quick Actions</div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:9px">
              <div onclick="showPanel('ss')" class="glass" style="display:flex;flex-direction:column;align-items:center;gap:7px;padding:12px 8px;border-radius:10px;cursor:pointer;transition:.2s" onmouseover="this.style.borderColor='var(--yellow)'" onmouseout="this.style.borderColor='var(--border)'">
                <div style="width:34px;height:34px;border-radius:50%;background:var(--yellow-dim);display:flex;align-items:center;justify-content:center"><span class="ms material-symbols-outlined" style="font-size:17px;color:var(--yellow)">support_agent</span></div>
                <span style="font-size:11px;font-weight:600;color:var(--white)">Support Site</span>
              </div>
              <div onclick="showPanel('rg')" class="glass" style="display:flex;flex-direction:column;align-items:center;gap:7px;padding:12px 8px;border-radius:10px;cursor:pointer;transition:.2s" onmouseover="this.style.borderColor='var(--yellow)'" onmouseout="this.style.borderColor='var(--border)'">
                <div style="width:34px;height:34px;border-radius:50%;background:rgba(34,197,94,.12);display:flex;align-items:center;justify-content:center"><span class="ms material-symbols-outlined" style="font-size:17px;color:var(--green)">receipt_long</span></div>
                <span style="font-size:11px;font-weight:600;color:var(--white)">Receipt Gen</span>
              </div>
              <div onclick="showPanel('cr')" class="glass" style="display:flex;flex-direction:column;align-items:center;gap:7px;padding:12px 8px;border-radius:10px;cursor:pointer;transition:.2s" onmouseover="this.style.borderColor='var(--yellow)'" onmouseout="this.style.borderColor='var(--border)'">
                <div style="width:34px;height:34px;border-radius:50%;background:rgba(59,130,246,.12);display:flex;align-items:center;justify-content:center"><span class="ms material-symbols-outlined" style="font-size:17px;color:var(--blue)">receipt</span></div>
                <span style="font-size:11px;font-weight:600;color:var(--white)">Crypto Rec.</span>
              </div>
              <div onclick="showPanel('referrals')" class="glass" style="display:flex;flex-direction:column;align-items:center;gap:7px;padding:12px 8px;border-radius:10px;cursor:pointer;transition:.2s" onmouseover="this.style.borderColor='var(--yellow)'" onmouseout="this.style.borderColor='var(--border)'">
                <div style="width:34px;height:34px;border-radius:50%;background:var(--yellow-dim);display:flex;align-items:center;justify-content:center"><span class="ms material-symbols-outlined" style="font-size:17px;color:var(--yellow)">group_add</span></div>
                <span style="font-size:11px;font-weight:600;color:var(--white)">Referrals</span>
              </div>
            </div>
          </div>
        </div>
        <div class="g3" style="margin-bottom:14px">
          <div class="stat y"><div class="stat-ic y"><span class="ms material-symbols-outlined">support_agent</span></div><div class="stat-lbl">Support Sites</div><div class="stat-val" id="st-sites">0</div></div>
          <div class="stat g"><div class="stat-ic g"><span class="ms material-symbols-outlined">receipt_long</span></div><div class="stat-lbl">Receipts</div><div class="stat-val" id="st-recs">0</div></div>
          <div class="stat b"><div class="stat-ic b"><span class="ms material-symbols-outlined">group_add</span></div><div class="stat-lbl">Referral Earned</div><div class="stat-val" id="st-refearned">$0</div></div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 280px;gap:14px">
          <div class="glass" style="overflow:hidden">
            <div style="padding:14px 14px 0;display:flex;justify-content:space-between;align-items:center"><span style="font-weight:800;font-size:.9rem">Recent Activity</span><a onclick="showPanel('activity')" style="font-size:12px;color:var(--yellow);cursor:pointer;font-weight:600">View All</a></div>
            <div style="overflow-x:auto"><table class="tbl" style="min-width:480px"><thead><tr><th>Transaction</th><th>Type</th><th>Date</th><th>Amount</th></tr></thead><tbody id="htx"><tr><td colspan="4" style="text-align:center;color:var(--gray);padding:20px">No transactions yet</td></tr></tbody></table></div>
          </div>
          <div class="glass" style="padding:16px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><span style="font-weight:800;font-size:.85rem">Balance Trend</span><span style="font-size:9px;background:var(--surface2);border:1px solid var(--border);padding:2px 7px;border-radius:4px;color:var(--gray);font-weight:600;text-transform:uppercase">7D</span></div>
            <div class="chart-bars" id="chart"></div>
            <div style="display:grid;grid-template-columns:repeat(7,1fr);gap:4px;margin-top:5px;text-align:center"><span class="cd">M</span><span class="cd">T</span><span class="cd">W</span><span class="cd">T</span><span class="cd">F</span><span class="cd">S</span><span class="cd" style="color:var(--yellow)">S</span></div>
          </div>
        </div>
      </div>

      <!-- WALLET -->
      <div class="panel" id="panel-wallet">
        <div class="ph"><h1>Wallet</h1><p>Your balance and full transaction history.</p></div>
        <div class="bal-card glass" style="margin-bottom:14px">
          <div class="bal-lbl">Available Balance</div><div class="bal-amt">$<span id="wbal">0.00</span></div>
          <div class="bal-grow"><span class="material-symbols-outlined ms" style="font-size:15px">account_balance_wallet</span>Toolyvans Wallet</div>
          <div class="bal-acts"><button class="btn-sm" onclick="showPanel('deposit')"><div class="blob"></div><div class="inn"><span class="material-symbols-outlined ms" style="font-size:13px">add_circle</span>Deposit Funds</div></button></div>
        </div>
        <div class="glass" style="overflow:hidden"><div style="padding:14px 14px 0"><span style="font-weight:800;font-size:.9rem">All Transactions</span></div><div style="overflow-x:auto"><table class="tbl" style="min-width:480px"><thead><tr><th>Transaction</th><th>Type</th><th>Date</th><th>Amount</th></tr></thead><tbody id="wtx"></tbody></table></div></div>
      </div>

      <!-- REFERRALS -->
      <div class="panel" id="panel-referrals">
        <div class="ph"><h1>Referral Program</h1><p>Earn $${REFERRAL_BONUS} for every friend you refer.</p></div>
        <div class="ref-box glass-yellow">
          <div style="flex:1">
            <div style="font-size:11px;font-weight:700;color:var(--yellow);text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">Your Referral Code</div>
            <div class="ref-code" id="ref-code-display">—</div>
            <div style="font-size:12px;color:var(--gray);margin-top:4px">Share this code. Each signup earns you <strong style="color:var(--yellow)">$${REFERRAL_BONUS}</strong> instantly.</div>
          </div>
          <button class="btn-sm" onclick="cpRef()"><div class="blob"></div><div class="inn"><span class="material-symbols-outlined ms" style="font-size:13px">content_copy</span>Copy Code</button>
          <button class="btn-sm" style="margin-left:6px" onclick="cpRefLink()"><div class="blob"></div><div class="inn"><span class="material-symbols-outlined ms" style="font-size:13px">share</span>Share Link</div></button>
        </div>
        <div class="g2" style="margin-bottom:14px">
          <div class="stat y"><div class="stat-ic y"><span class="ms material-symbols-outlined">group</span></div><div class="stat-lbl">Total Referrals</div><div class="stat-val" id="ref-count">0</div></div>
          <div class="stat g"><div class="stat-ic g"><span class="ms material-symbols-outlined">payments</span></div><div class="stat-lbl">Total Earned</div><div class="stat-val" id="ref-earned">$0</div></div>
        </div>
        <div class="glass" style="overflow:hidden"><div style="padding:14px 14px 0"><span style="font-weight:800;font-size:.9rem">Referral History</span></div><div style="overflow-x:auto"><table class="tbl"><thead><tr><th>Name</th><th>Date</th><th>Bonus</th></tr></thead><tbody id="ref-tbl"><tr><td colspan="3" style="text-align:center;color:var(--gray);padding:20px">No referrals yet</td></tr></tbody></table></div></div>
      </div>

      <!-- TOOLS -->
      <div class="panel" id="panel-tools">
        <div class="ph"><h1>Tools Marketplace</h1><p>Professional fintech tools billed from your wallet.</p></div>
        <div class="tools-grid">
          <div class="tool-card y" onclick="showPanel('ss')"><div class="tool-card-ic y"><span class="material-symbols-outlined ms" style="font-size:26px;color:var(--yellow)">support_agent</span></div><div class="tool-card-name">Support Site Generator</div><div class="tool-card-desc">Branded trading-platform support microsites with floating contact buttons, custom themes and shareable URLs.</div><div class="tool-card-price"><strong>$3</strong>/day</div></div>
          <div class="tool-card g" onclick="showPanel('rg')"><div class="tool-card-ic g"><span class="material-symbols-outlined ms" style="font-size:26px;color:var(--green)">receipt_long</span></div><div class="tool-card-name">Trading Receipt Generator</div><div class="tool-card-desc">Fully branded trade receipts for any exchange. Buy/Sell/Deposit/Withdraw with platform styling.</div><div class="tool-card-price"><strong>$2</strong>/day</div></div>
          <div class="tool-card b" onclick="showPanel('cr')"><div class="tool-card-ic b"><span class="material-symbols-outlined ms" style="font-size:26px;color:var(--blue)">receipt</span></div><div class="tool-card-name">Crypto Receipt Generator</div><div class="tool-card-desc">Styled crypto receipts for Binance, Coinbase, Cash App, PayPal, Zelle and 7 more brands.</div><div class="tool-card-price"><strong>$2</strong>/day</div></div>
        </div>
      </div>

      <!-- SUPPORT SITE PANEL -->
      <div class="panel" id="panel-ss">
        <div class="ph"><h1>Support Site Generator</h1><p>$3/day · Billed from wallet balance</p></div>
        <div class="fcard" style="margin-bottom:20px">
          <div class="fcard-hdr"><div class="back-btn" onclick="showPanel('tools')"><span class="ms material-symbols-outlined">arrow_back</span></div><div><div style="font-weight:700;font-size:14px">New Support Site</div><div style="font-size:11px;color:var(--gray)">Configure your branded microsite</div></div></div>
          <div class="fcard-body">
            <div class="fg"><label class="fl">Select Platform</label><div class="pgrid" id="ss-pgrid"></div><input type="hidden" id="ss-plt"/></div>
            <div class="fg"><label class="fl">Contact Method</label>
              <div class="cgrid">
                <div class="copt" data-m="email" onclick="selCt('email')"><span class="ms material-symbols-outlined">mail</span><span class="cl">Email</span></div>
                <div class="copt" data-m="whatsapp" onclick="selCt('whatsapp')"><span class="ms material-symbols-outlined">chat</span><span class="cl">WhatsApp</span></div>
                <div class="copt" data-m="telegram" onclick="selCt('telegram')"><span class="ms material-symbols-outlined">send</span><span class="cl">Telegram</span></div>
                <div class="copt" data-m="chatbot" onclick="selCt('chatbot')"><span class="ms material-symbols-outlined">smart_toy</span><span class="cl">Chatbot</span></div>
              </div>
              <input type="hidden" id="ss-cm"/>
            </div>
            <div class="fg" id="ss-cvg" style="display:none"><label class="fl" id="ss-cvl">Contact Value</label><input type="text" class="fi" id="ss-cv" placeholder="Enter contact details"/></div>
            <div class="fg" id="ss-cbg" style="display:none"><label class="fl">Chatbot Embed Code</label><textarea class="fi" id="ss-cbc" rows="3" placeholder="Paste chat widget script…"></textarea></div>
            <div class="fg"><label class="fl">Duration</label>
              <div class="sdr-hdr"><span style="font-size:12px;color:var(--gray)">1–30 days</span><div class="sdr-val"><span id="ss-dd">7</span> days</div></div>
              <input type="range" class="rng" min="1" max="30" value="7" id="ss-ds" oninput="updD('ss',this.value)"/>
              <div class="sdr-lbl"><span>1d</span><span>15d</span><span>30d</span></div>
            </div>
            <div class="cost-box"><div><div style="font-weight:700;font-size:13px;color:var(--white)">Total Cost</div><div style="font-size:12px;color:var(--gray)" id="ss-cbd">7 days × $3/day</div></div><div class="cost-big">$<span id="ss-tc">21.00</span></div></div>
            <button class="btn" onclick="genSS()" id="ss-btn" style="width:100%"><div class="blob"></div><div class="inn"><span class="material-symbols-outlined ms" style="font-size:15px">auto_awesome</span>Generate Support Site</div></button>
          </div>
        </div>
        <div style="font-weight:800;font-size:.9rem;margin-bottom:10px">My Support Sites</div>
        <div id="ss-list"><div style="text-align:center;color:var(--gray);padding:18px;background:var(--surface);border-radius:10px;border:1px solid var(--border)">No support sites yet</div></div>
      </div>

      <!-- RECEIPT GEN PANEL -->
      <div class="panel" id="panel-rg">
        <div class="ph"><h1>Trading Receipt Generator</h1><p>$2/day · Billed from wallet balance</p></div>
        <div class="fcard" style="margin-bottom:20px">
          <div class="fcard-hdr"><div class="back-btn" onclick="showPanel('tools')"><span class="ms material-symbols-outlined">arrow_back</span></div><div><div style="font-weight:700;font-size:14px">New Trading Receipt</div><div style="font-size:11px;color:var(--gray)">Generate a branded trade receipt</div></div></div>
          <div class="fcard-body">
            <div class="fg"><label class="fl">Platform</label><div class="pgrid" id="rg-pgrid"></div><input type="hidden" id="rg-plt"/></div>
            <div class="g2">
              <div class="fg"><label class="fl">Trade Type</label><div class="sel-wrap"><select class="sel" id="rg-tt"><option value="BUY">Buy</option><option value="SELL">Sell</option><option value="DEPOSIT">Deposit</option><option value="WITHDRAWAL">Withdrawal</option><option value="TRANSFER">Transfer</option></select><div class="sel-arr"><span class="ms material-symbols-outlined">expand_more</span></div></div></div>
              <div class="fg"><label class="fl">Asset / Coin</label><input type="text" class="fi" id="rg-ast" placeholder="BTC, ETH, USDT…"/></div>
            </div>
            <div class="g3">
              <div class="fg"><label class="fl">Amount</label><input type="number" class="fi" id="rg-amt" placeholder="0.0000"/></div>
              <div class="fg"><label class="fl">Price (USD)</label><input type="number" class="fi" id="rg-prc" placeholder="43500"/></div>
              <div class="fg"><label class="fl">Fee (USD)</label><input type="number" class="fi" id="rg-fee" placeholder="0.00"/></div>
            </div>
            <div class="g2">
              <div class="fg"><label class="fl">Trade Date & Time</label><input type="datetime-local" class="fi" id="rg-dt"/></div>
              <div class="fg"><label class="fl">Transaction ID</label><input type="text" class="fi" id="rg-txid" placeholder="0x1a2b3c…"/></div>
            </div>
            <div class="fg"><label class="fl">Wallet Address (optional)</label><input type="text" class="fi" id="rg-wa" placeholder="0x… or leave blank"/></div>
            <div class="fg"><label class="fl">Duration</label>
              <div class="sdr-hdr"><span style="font-size:12px;color:var(--gray)">1–30 days</span><div class="sdr-val"><span id="rg-dd">7</span> days</div></div>
              <input type="range" class="rng" min="1" max="30" value="7" id="rg-ds" oninput="updD('rg',this.value)"/>
              <div class="sdr-lbl"><span>1d</span><span>15d</span><span>30d</span></div>
            </div>
            <div class="cost-box"><div><div style="font-weight:700;font-size:13px;color:var(--white)">Total Cost</div><div style="font-size:12px;color:var(--gray)" id="rg-cbd">7 days × $2/day</div></div><div class="cost-big">$<span id="rg-tc">14.00</span></div></div>
            <button class="btn" onclick="genRG()" id="rg-btn" style="width:100%"><div class="blob"></div><div class="inn"><span class="material-symbols-outlined ms" style="font-size:15px">receipt_long</span>Generate Receipt</div></button>
          </div>
        </div>
        <div style="font-weight:800;font-size:.9rem;margin-bottom:10px">My Receipts</div>
        <div id="rg-list"><div style="text-align:center;color:var(--gray);padding:18px;background:var(--surface);border-radius:10px;border:1px solid var(--border)">No receipts yet</div></div>
      </div>

      <!-- CRYPTO RECEIPT PANEL -->
      <div class="panel" id="panel-cr">
        <div class="ph"><h1>Crypto Receipt Generator</h1><p>$2/day · Billed from wallet balance</p></div>
        <div class="fcard" style="margin-bottom:20px">
          <div class="fcard-hdr"><div class="back-btn" onclick="showPanel('tools')"><span class="ms material-symbols-outlined">arrow_back</span></div><div><div style="font-weight:700;font-size:14px">New Crypto Receipt</div><div style="font-size:11px;color:var(--gray)">Styled receipt from crypto-receipt builder</div></div></div>
          <div class="fcard-body">
            <div class="fg"><label class="fl">Receipt Type</label>
              <div style="display:flex;gap:8px;margin-top:4px"><button class="atab on" id="tab-crypto" onclick="setCRType('crypto')" style="flex:1;padding:8px;border-radius:8px">Crypto Exchange</button><button class="atab" id="tab-bank" onclick="setCRType('bank')" style="flex:1;padding:8px;border-radius:8px">Bank / App</button></div>
            </div>
            <div class="fg"><label class="fl">Select Brand</label><div class="bgrid" id="cr-bgrid"></div><input type="hidden" id="cr-brand"/></div>
            <div id="cr-crypto-f">
              <div class="g2">
                <div class="fg"><label class="fl">Coin / Token</label><input type="text" class="fi" id="cr-coin" placeholder="USDT"/></div>
                <div class="fg"><label class="fl">Network</label><div class="sel-wrap"><select class="sel" id="cr-net"><option>TRC20</option><option>ERC20</option><option>Bitcoin</option><option>BEP20</option><option>Solana</option><option>Polygon</option></select><div class="sel-arr"><span class="ms material-symbols-outlined">expand_more</span></div></div></div>
              </div>
            </div>
            <div class="g2">
              <div class="fg"><label class="fl">Date & Time</label><input type="datetime-local" class="fi" id="cr-dt"/></div>
              <div class="fg"><label class="fl">Amount</label><input type="text" class="fi" id="cr-amt" placeholder="10,000.00"/></div>
            </div>
            <div class="g2">
              <div class="fg"><label class="fl" id="cr-addr-l">Wallet Address</label><input type="text" class="fi" id="cr-addr" placeholder="0x… / $cashtag"/></div>
              <div class="fg"><label class="fl" id="cr-txid-l">TXID / Receipt ID</label><input type="text" class="fi" id="cr-txid" placeholder="Auto-generated or paste"/></div>
            </div>
            <div class="fg"><label class="fl">Status</label>
              <div class="sgrid">
                <div class="sopt on" onclick="selSt('completed')">✓ Completed</div>
                <div class="sopt" onclick="selSt('pending')">⏳ Pending</div>
                <div class="sopt" onclick="selSt('canceled')">✕ Canceled</div>
              </div>
              <input type="hidden" id="cr-status" value="completed"/>
            </div>
            <div class="fg"><label class="fl">Duration</label>
              <div class="sdr-hdr"><span style="font-size:12px;color:var(--gray)">1–30 days</span><div class="sdr-val"><span id="cr-dd">7</span> days</div></div>
              <input type="range" class="rng" min="1" max="30" value="7" id="cr-ds" oninput="updD('cr',this.value)"/>
              <div class="sdr-lbl"><span>1d</span><span>15d</span><span>30d</span></div>
            </div>
            <div class="cost-box"><div><div style="font-weight:700;font-size:13px;color:var(--white)">Total Cost</div><div style="font-size:12px;color:var(--gray)" id="cr-cbd">7 days × $2/day</div></div><div class="cost-big">$<span id="cr-tc">14.00</span></div></div>
            <button class="btn" onclick="genCR()" id="cr-btn" style="width:100%"><div class="blob"></div><div class="inn"><span class="material-symbols-outlined ms" style="font-size:15px">receipt</span>Generate Crypto Receipt</div></button>
          </div>
        </div>
        <div style="font-weight:800;font-size:.9rem;margin-bottom:10px">My Crypto Receipts</div>
        <div id="cr-list"><div style="text-align:center;color:var(--gray);padding:18px;background:var(--surface);border-radius:10px;border:1px solid var(--border)">No crypto receipts yet</div></div>
      </div>

      <!-- DEPOSIT -->
      <div class="panel" id="panel-deposit">
        <div class="ph"><h1>Deposit Funds</h1><p>Add balance to your Toolyvans wallet via Paystack.</p></div>
        <div class="glass" style="padding:22px;max-width:480px">
          <div class="fg"><label class="fl">Quick Select</label><div class="dchips"><div class="dchip" onclick="selDep(10)">$10</div><div class="dchip" onclick="selDep(25)">$25</div><div class="dchip" onclick="selDep(50)">$50</div><div class="dchip" onclick="selDep(100)">$100</div><div class="dchip" onclick="selDep(250)">$250</div><div class="dchip" onclick="selDep(500)">$500</div></div></div>
          <div class="fg"><label class="fl">Custom Amount (USD)</label><input type="number" class="fi" id="dep-amt" placeholder="Minimum $5" min="5"/></div>
          <div style="background:var(--yellow-dim);border:1px solid var(--border-yellow);border-radius:var(--radius);padding:12px;margin-bottom:16px;font-size:12px;color:var(--yellow)"><span class="material-symbols-outlined ms" style="font-size:13px;vertical-align:middle;margin-right:5px">info</span>Payments processed securely via Paystack. Balance updates immediately.</div>
          <button class="btn" onclick="doDeposit()" id="dep-btn" style="width:100%"><div class="blob"></div><div class="inn"><span class="material-symbols-outlined ms" style="font-size:15px">payments</span>Pay with Paystack</div></button>
        </div>
      </div>

      <!-- ACTIVITY -->
      <div class="panel" id="panel-activity">
        <div class="ph"><h1>Activity Log</h1><p>Full transaction and tool usage history.</p></div>
        <div class="glass" style="overflow:hidden"><div style="padding:14px 14px 0"><span style="font-weight:800;font-size:.9rem">All Transactions</span></div><div style="overflow-x:auto"><table class="tbl" style="min-width:480px"><thead><tr><th>Transaction</th><th>Type</th><th>Date</th><th>Amount</th></tr></thead><tbody id="atx"></tbody></table></div></div>
      </div>

      <!-- ADMIN -->
      <div class="panel" id="panel-admin">
        <div class="ph"><h1>Admin Dashboard</h1><p>Platform overview and user management.</p></div>
        <div class="admin-grid" id="admin-stats-grid">
          <div class="stat y"><div class="stat-ic y"><span class="ms material-symbols-outlined">group</span></div><div class="stat-lbl">Total Users</div><div class="stat-val" id="ad-users">—</div></div>
          <div class="stat g"><div class="stat-ic g"><span class="ms material-symbols-outlined">payments</span></div><div class="stat-lbl">Total Deposits</div><div class="stat-val" id="ad-dep">—</div></div>
          <div class="stat b"><div class="stat-ic b"><span class="ms material-symbols-outlined">build</span></div><div class="stat-lbl">Tool Revenue</div><div class="stat-val" id="ad-rev">—</div></div>
          <div class="stat r"><div class="stat-ic r"><span class="ms material-symbols-outlined">receipt_long</span></div><div class="stat-lbl">Items Generated</div><div class="stat-val" id="ad-items">—</div></div>
        </div>
        <div class="glass" style="overflow:hidden;margin-bottom:14px"><div style="padding:14px 14px 0;display:flex;justify-content:space-between;align-items:center"><span style="font-weight:800;font-size:.9rem">All Users</span></div><div style="overflow-x:auto"><table class="tbl"><thead><tr><th>Name</th><th>Email</th><th>Balance</th><th>Joined</th><th>Action</th></tr></thead><tbody id="ad-users-tbl"><tr><td colspan="5" style="text-align:center;color:var(--gray);padding:20px">Loading…</td></tr></tbody></table></div></div>
        <div class="glass" style="padding:20px;max-width:480px">
          <div style="font-weight:800;font-size:.9rem;margin-bottom:14px">Credit User Wallet</div>
          <div class="fg"><label class="fl">User ID</label><input type="text" class="fi" id="ad-uid" placeholder="Paste user ID"/></div>
          <div class="g2">
            <div class="fg"><label class="fl">Amount (USD)</label><input type="number" class="fi" id="ad-amt" placeholder="10.00"/></div>
            <div class="fg"><label class="fl">Note</label><input type="text" class="fi" id="ad-note" placeholder="Admin credit"/></div>
          </div>
          <button class="btn-sm" onclick="adminCredit()" style="margin-top:4px"><div class="blob"></div><div class="inn"><span class="material-symbols-outlined ms" style="font-size:13px">add_card</span>Credit Wallet</div></button>
        </div>
      </div>

    </div>
  </div>
</div><!-- /dash-pg -->
</div><!-- /app -->

<script>
const PAYSTACK_KEY='pk_live_69fcc7c11f24d782bb103fddf833dee1daa85e9d';
let CU=null,TOKEN=localStorage.getItem('tv_tok');
const _bo={};

const PLATS=[
  {k:'binance',n:'Binance',e:'🟡',logo:'https://bin.bnbstatic.com/static/images/common/favicon.ico',bg:'#181A20'},
  {k:'bybit',n:'Bybit',e:'🟠',logo:'https://www.bybit.com/favicon.ico',bg:'#1C1C1E'},
  {k:'coinbase',n:'Coinbase',e:'🔵',logo:'https://www.coinbase.com/favicon.ico',bg:'#0052FF'},
  {k:'metamask',n:'MetaMask',e:'🦊',logo:'https://raw.githubusercontent.com/MetaMask/brand-resources/master/SVG/SVG_MetaMask_Icon_Color.svg',bg:'#F6851B'},
  {k:'trustwallet',n:'Trust',e:'🔷',logo:'https://trustwallet.com/assets/images/media/assets/TWT.png',bg:'#3375BB'},
  {k:'robinhood',n:'Robin',e:'🟢',logo:'https://robinhood.com/favicon.ico',bg:'#00C805'},
  {k:'phantom',n:'Phantom',e:'👻',logo:'https://phantom.app/img/phantom-logo.png',bg:'#9945FF'},
  {k:'kraken',n:'Kraken',e:'🐙',logo:'https://www.kraken.com/favicon.ico',bg:'#5741D9'},
  {k:'kucoin',n:'KuCoin',e:'🐢',logo:'https://www.kucoin.com/favicon.ico',bg:'#23AF91'},
  {k:'okx',n:'OKX',e:'⚫',logo:'https://static.okx.com/cdn/assets/imgs/221/9E073F600D8C8D77.png',bg:'#000'}
];

const CR_BRANDS={
  crypto:[
    {k:'Binance',logo:'https://bin.bnbstatic.com/static/images/common/favicon.ico'},
    {k:'Coinbase',logo:'https://www.coinbase.com/favicon.ico'},
    {k:'OKX',logo:'https://static.okx.com/cdn/assets/imgs/221/9E073F600D8C8D77.png'},
    {k:'Kraken',logo:'https://www.kraken.com/favicon.ico'},
    {k:'Bybit',logo:'https://www.bybit.com/favicon.ico'},
    {k:'KuCoin',logo:'https://www.kucoin.com/favicon.ico'}
  ],
  bank:[
    {k:'Cash App',logo:'https://cash.app/favicon.ico'},
    {k:'Zelle',logo:'https://www.zellepay.com/favicon.ico'},
    {k:'PayPal',logo:'https://www.paypal.com/favicon.ico'},
    {k:'Chase',logo:'https://www.chase.com/favicon.ico'},
    {k:'Bank of America',logo:'https://www.bankofamerica.com/favicon.ico'},
    {k:'Wells Fargo',logo:'https://www.wellsfargo.com/favicon.ico'}
  ]
};
let crType='crypto';

// ── INIT ──────────────────────────────────────────────────────
async function init(){
  buildPlatGrids(); buildCRBrands('crypto'); buildPlatStrip();
  const ref=new URLSearchParams(location.search).get('ref');
  if(ref) g('rref')&&(g('rref').value=ref.toUpperCase());
  if(TOKEN){
    try{ CU=await api('GET','/api/auth/me'); showDash(); await loadDash(); }
    catch(_){ localStorage.removeItem('tv_tok'); TOKEN=null; showLanding(); }
  } else { showLanding(); }
  const pref=new URLSearchParams(location.search).get('reference')||new URLSearchParams(location.search).get('trxref');
  if(pref&&TOKEN){ await verifyPay(pref); history.replaceState({},'','/'); }
  setTimeout(()=>g('ldr').classList.add('gone'),600);
}

async function api(method,path,body){
  const r=await fetch(path,{method,headers:{'Content-Type':'application/json',...(TOKEN?{'Authorization':'Bearer '+TOKEN}:{})},body:body?JSON.stringify(body):undefined});
  const d=await r.json(); if(!r.ok) throw new Error(d.error||'Request failed'); return d;
}

// ── PAGE SHOW ─────────────────────────────────────────────────
function showLanding(){ g('land-pg').classList.add('active'); g('auth-pg').classList.remove('active'); g('dash-pg').classList.remove('active'); }
function showAuth(tab='login'){ g('land-pg').classList.remove('active'); g('auth-pg').classList.add('active'); g('dash-pg').classList.remove('active'); if(tab==='register')switchTab('register'); }
function showDash(){ g('land-pg').classList.remove('active'); g('auth-pg').classList.remove('active'); g('dash-pg').classList.add('active'); }
function scrollTo(id){ document.getElementById(id)?.scrollIntoView({behavior:'smooth'}); }

// ── AUTH ──────────────────────────────────────────────────────
function switchTab(t){
  document.querySelectorAll('.atab').forEach((el,i)=>el.classList.toggle('on',(t==='login'&&i===0)||(t==='register'&&i===1)));
  g('lf').style.display=t==='login'?'block':'none';
  g('rf').style.display=t==='register'?'block':'none';
}
async function doLogin(){
  const e=g('le').value.trim(),p=g('lp').value,err=g('lerr');
  err.style.display='none';
  if(!e||!p){err.textContent='Fill all fields';err.style.display='block';return;}
  setLoad('lbtn',true);
  try{
    const d=await api('POST','/api/auth/login',{email:e,password:p});
    TOKEN=d.token; CU=d.user; localStorage.setItem('tv_tok',TOKEN);
    showDash(); showPanel('home'); await loadDash();
    toast('Welcome back, '+CU.name+'! 👋','success');
  }catch(ex){err.textContent=ex.message;err.style.display='block';}
  setLoad('lbtn',false,'<span class="material-symbols-outlined ms" style="font-size:15px">login</span>Sign In');
}
async function doReg(){
  const n=g('rn').value.trim(),e=g('re').value.trim(),p=g('rp').value,ref=g('rref')?.value.trim(),err=g('rerr');
  err.style.display='none';
  if(!n||!e||!p){err.textContent='Fill all fields';err.style.display='block';return;}
  if(p.length<6){err.textContent='Password min 6 characters';err.style.display='block';return;}
  setLoad('rbtn',true);
  try{
    const d=await api('POST','/api/auth/register',{name:n,email:e,password:p,referralCode:ref||''});
    TOKEN=d.token; CU=d.user; localStorage.setItem('tv_tok',TOKEN);
    showDash(); showPanel('home'); await loadDash();
    toast('Welcome to Toolyvans! 🎉','success');
  }catch(ex){err.textContent=ex.message;err.style.display='block';}
  setLoad('rbtn',false,'<span class="material-symbols-outlined ms" style="font-size:15px">person_add</span>Create Account');
}
function doLogout(){ TOKEN=null; CU=null; localStorage.removeItem('tv_tok'); showLanding(); toast('Signed out','success'); }

// ── NAV ───────────────────────────────────────────────────────
const PT={home:'Dashboard',wallet:'Wallet',referrals:'Referral Program',tools:'Tools Marketplace',ss:'Support Site Generator',rg:'Trading Receipt Generator',cr:'Crypto Receipt Generator',deposit:'Deposit Funds',activity:'Activity Log',admin:'Admin Dashboard'};
function showPanel(n){
  document.querySelectorAll('.ni').forEach(el=>el.classList.toggle('on',el.dataset.p===n));
  document.querySelectorAll('.panel').forEach(el=>el.classList.toggle('on',el.id==='panel-'+n));
  g('tbtitle').textContent=PT[n]||'Dashboard';
  if(n==='ss') loadSSList();
  if(n==='rg') loadRGList();
  if(n==='cr') loadCRList();
  if(n==='wallet'||n==='activity') loadAllTx();
  if(n==='referrals') loadReferrals();
  if(n==='admin') loadAdmin();
}

// ── DASHBOARD DATA ────────────────────────────────────────────
async function loadDash(){
  if(!CU) return;
  try{
    const d=await api('GET','/api/dashboard');
    updUI(d.balance);
    g('st-sites').textContent=d.stats.sites;
    g('st-recs').textContent=d.stats.receipts;
    g('st-refearned').textContent='$'+d.stats.referralEarnings;
    if(d.referralCode){ g('ref-code-display').textContent=d.referralCode; g('ref-count').textContent=d.stats.referrals; g('ref-earned').textContent='$'+d.stats.referralEarnings; }
    renderTx('htx',d.transactions.slice(0,5));
    renderChart(d.balance);
    if(CU.isAdmin){ g('admin-nav-item').style.display='block'; }
  }catch(e){console.error(e);}
}
function updUI(bal){
  const b=parseFloat(bal||0).toFixed(2);
  if(!CU) return;
  g('sbname').textContent=CU.name;
  g('sbavt').textContent=CU.name.charAt(0).toUpperCase();
  g('sbbal').textContent=b; g('hbal').textContent=b; g('wbal')&&(g('wbal').textContent=b);
  g('wname').textContent=CU.name.split(' ')[0];
}
async function loadAllTx(){
  try{ const d=await api('GET','/api/dashboard'); updUI(d.balance); renderTx('wtx',d.transactions); renderTx('atx',d.transactions); }catch(e){}
}
function renderTx(id,txs){
  const tb=g(id); if(!tb) return;
  if(!txs||!txs.length){tb.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--gray);padding:20px">No transactions yet</td></tr>';return;}
  tb.innerHTML=txs.map(t=>{
    const pos=t.amount>0,ic=t.icon||(pos?'add_task':'remove_circle');
    const bc=t.type==='deposit'?'bdg-g':t.type==='referral'?'bdg-y':'bdg-b';
    const dt=new Date(t.createdAt).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'});
    return \`<tr><td><div style="display:flex;align-items:center;gap:9px"><div style="width:30px;height:30px;border-radius:8px;background:var(--surface2);display:flex;align-items:center;justify-content:center;flex-shrink:0"><span class="ms material-symbols-outlined" style="font-size:15px;color:\${pos?'var(--green)':'var(--yellow)'}">\${ic}</span></div><div><div style="font-size:13px;font-weight:500">\${t.description}</div><div style="font-size:11px;color:var(--gray)">\${t.reference||''}</div></div></div></td><td><span class="bdg \${bc}">\${t.type}</span></td><td style="color:var(--gray);font-size:12px">\${dt}</td><td style="font-weight:700;color:\${pos?'var(--green)':'var(--white)'}">\${pos?'+':''}\$\${Math.abs(t.amount).toFixed(2)}</td></tr>\`;
  }).join('');
}
function renderChart(bal){
  const h=[40,58,50,84,68,92,100],max=100;
  g('chart').innerHTML=h.map((v,i)=>\`<div class="cb-w"><div class="cb \${i===6?'now':''}" style="height:\${v}%" title="\$\${(bal*v/100).toFixed(0)}"></div></div>\`).join('');
}

// ── REFERRALS ─────────────────────────────────────────────────
async function loadReferrals(){
  try{
    const d=await api('GET','/api/referrals');
    g('ref-count').textContent=d.referrals.length;
    g('ref-earned').textContent='$'+(d.referrals.length*d.bonus);
    const tb=g('ref-tbl');
    if(!d.referrals.length){tb.innerHTML='<tr><td colspan="3" style="text-align:center;color:var(--gray);padding:20px">No referrals yet. Share your code!</td></tr>';return;}
    tb.innerHTML=d.referrals.map(r=>\`<tr><td style="font-weight:500">\${r.referredName}</td><td style="color:var(--gray);font-size:12px">\${new Date(r.createdAt).toLocaleDateString()}</td><td style="color:var(--green);font-weight:700">+\$\${r.bonus}</td></tr>\`).join('');
  }catch(e){}
}
function cpRef(){ navigator.clipboard.writeText(g('ref-code-display').textContent).then(()=>toast('Referral code copied!','success')); }
function cpRefLink(){ navigator.clipboard.writeText(location.origin+'?ref='+(g('ref-code-display').textContent||'')).then(()=>toast('Referral link copied!','success')); }

// ── PLATFORM GRIDS ────────────────────────────────────────────
function buildPlatGrids(){
  ['ss','rg'].forEach(px=>{
    g(px+'-pgrid').innerHTML=PLATS.map(p=>\`<div class="popt" data-k="\${p.k}" onclick="selPlt('\${px}','\${p.k}',this)">
      <div style="width:32px;height:32px;border-radius:50%;background:\${p.bg};overflow:hidden;display:flex;align-items:center;justify-content:center;border:2px solid rgba(255,255,255,0.1)">
        <img src="\${p.logo}" width="20" height="20" style="object-fit:contain" onerror="this.parentElement.innerHTML='\${p.e}'"/>
      </div>
      <div class="pn">\${p.n}</div></div>\`).join('');
  });
}
function selPlt(px,k,el){ document.querySelectorAll('#'+px+'-pgrid .popt').forEach(e=>e.classList.remove('on')); el.classList.add('on'); g(px+'-plt').value=k; }

function buildPlatStrip(){
  const el=g('plat-strip-land'); if(!el) return;
  el.innerHTML=PLATS.map(p=>\`<div class="plat-item">
    <div style="width:24px;height:24px;border-radius:50%;background:\${p.bg};overflow:hidden;display:flex;align-items:center;justify-content:center">
      <img src="\${p.logo}" width="16" height="16" style="object-fit:contain" onerror="this.parentElement.innerHTML='\${p.e}'"/>
    </div>
    <span class="plat-item-name">\${p.n}</span></div>\`).join('');
}

function buildCRBrands(type){
  g('cr-bgrid').innerHTML=CR_BRANDS[type].map(b=>\`<div class="bopt" data-k="\${b.k}" onclick="selBrand(this,'\${b.k}')">
    <div style="width:24px;height:24px;border-radius:50%;background:#fff;overflow:hidden;display:flex;align-items:center;justify-content:center">
      <img src="\${b.logo}" width="18" height="18" style="object-fit:contain" onerror="this.style.display='none'"/>
    </div>
    <div class="bn">\${b.k}</div></div>\`).join('');
}
function selBrand(el,k){ document.querySelectorAll('.bopt').forEach(e=>e.classList.remove('on')); el.classList.add('on'); g('cr-brand').value=k; }
function setCRType(t){
  crType=t;
  g('tab-crypto').classList.toggle('on',t==='crypto');
  g('tab-bank').classList.toggle('on',t==='bank');
  g('cr-crypto-f').style.display=t==='crypto'?'block':'none';
  if(t==='bank'){g('cr-addr-l').textContent='Email / Account / $tag';g('cr-txid-l').textContent='Receipt / Conf. No.';}
  else{g('cr-addr-l').textContent='Wallet Address';g('cr-txid-l').textContent='TXID / Transaction Hash';}
  buildCRBrands(t); g('cr-brand').value='';
}
function selCt(m){
  document.querySelectorAll('.copt').forEach(el=>el.classList.toggle('on',el.dataset.m===m));
  g('ss-cm').value=m;
  const sh=m!=='chatbot';
  g('ss-cvg').style.display=sh?'block':'none';
  g('ss-cbg').style.display=!sh?'block':'none';
  const lm={email:'Email Address',whatsapp:'WhatsApp Number (+country code)',telegram:'Telegram Username'};
  const pm={email:'support@example.com',whatsapp:'+2348012345678',telegram:'@username'};
  if(sh){g('ss-cvl').textContent=lm[m]||'Contact Value';g('ss-cv').placeholder=pm[m]||'';}
}
function selSt(s){ document.querySelectorAll('.sopt').forEach(el=>el.classList.remove('on')); document.querySelector('.sopt:nth-child('+(s==='completed'?1:s==='pending'?2:3)+')').classList.add('on'); g('cr-status').value=s; }
function updD(px,v){ const pr=px==='ss'?3:2; g(px+'-dd').textContent=v; g(px+'-tc').textContent=(v*pr).toFixed(2); g(px+'-cbd').textContent=v+' days × $'+pr+'/day'; }

// ── TOOL 1: SUPPORT SITE ──────────────────────────────────────
async function genSS(){
  const plt=g('ss-plt').value,cm=g('ss-cm').value,cv=g('ss-cv').value.trim(),cb=g('ss-cbc')?.value.trim(),days=g('ss-ds').value;
  if(!plt){toast('Select a platform','error');return;}
  if(!cm){toast('Select a contact method','error');return;}
  if(cm!=='chatbot'&&!cv){toast('Enter contact details','error');return;}
  if(cm==='chatbot'&&!cb){toast('Paste chatbot code','error');return;}
  setLoad('ss-btn',true);
  try{ const r=await api('POST','/api/tools/support-site/generate',{platform:plt,contactMethod:cm,contactValue:cv,chatbotCode:cb||'',days}); CU.balance=r.newBalance; updUI(r.newBalance); toast('Support site generated! Cost: $'+r.cost,'success'); loadSSList(); }
  catch(ex){ toast(ex.message,'error'); }
  setLoad('ss-btn',false,'<span class="material-symbols-outlined ms" style="font-size:15px">auto_awesome</span>Generate Support Site');
}
async function loadSSList(){
  try{
    const d=await api('GET','/api/tools/support-site/list');
    const c=g('ss-list');
    if(!d.sites.length){c.innerHTML='<div style="text-align:center;color:var(--gray);padding:18px;background:var(--surface);border-radius:10px;border:1px solid var(--border)">No support sites yet</div>';return;}
    c.innerHTML=d.sites.map(s=>{
      const p=PLATS.find(pl=>pl.k===s.platform)||{e:'🌐',n:s.platform,logo:'',bg:'#333'};
      const exp=new Date()>new Date(s.expiresAt);
      const es=exp?'<span style="color:var(--red);font-size:11px">Expired</span>':'<span style="color:var(--green);font-size:11px">Active until '+new Date(s.expiresAt).toLocaleDateString()+'</span>';
      const url=location.origin+'/view/'+s.slug;
      return \`<div class="gen-item"><div style="display:flex;align-items:center;gap:10px">
        <div style="width:32px;height:32px;border-radius:50%;background:\${p.bg};overflow:hidden;display:flex;align-items:center;justify-content:center;border:2px solid rgba(255,255,255,.1)"><img src="\${p.logo}" width="20" height="20" style="object-fit:contain" onerror="this.parentElement.innerHTML='\${p.e}'"/></div>
        <div><div class="gen-nm">\${p.n} Support Site</div><div class="gen-mt">\${es} · \${s.contactMethod} · \${s.days}d · $\${s.totalCost}</div></div></div>
        <div class="gen-acts"><button class="cpbtn" onclick="cp('\${url}')"><span class="ms material-symbols-outlined">content_copy</span>Copy</button><a class="vwbtn" href="/view/\${s.slug}" target="_blank"><span class="ms material-symbols-outlined">open_in_new</span>View</a></div></div>\`;
    }).join('');
  }catch(e){}
}

// ── TOOL 2: RECEIPT GEN ───────────────────────────────────────
async function genRG(){
  const plt=g('rg-plt').value,tt=g('rg-tt').value,ast=g('rg-ast').value.trim(),amt=g('rg-amt').value,prc=g('rg-prc').value,fee=g('rg-fee').value,dt=g('rg-dt').value,txid=g('rg-txid').value.trim(),wa=g('rg-wa').value.trim(),days=g('rg-ds').value;
  if(!plt){toast('Select a platform','error');return;}
  if(!ast){toast('Enter asset name','error');return;}
  if(!amt||!prc){toast('Enter amount and price','error');return;}
  if(!dt){toast('Select trade date','error');return;}
  if(!txid){toast('Enter transaction ID','error');return;}
  setLoad('rg-btn',true);
  try{ const r=await api('POST','/api/tools/receipt/generate',{platform:plt,tradeType:tt,asset:ast,amount:amt,price:prc,totalValue:(parseFloat(amt)*parseFloat(prc)).toFixed(2),date:dt,txId:txid,walletAddress:wa,fee:fee||'0',days}); CU.balance=r.newBalance; updUI(r.newBalance); toast('Receipt generated! Cost: $'+r.cost,'success'); loadRGList(); }
  catch(ex){ toast(ex.message,'error'); }
  setLoad('rg-btn',false,'<span class="material-symbols-outlined ms" style="font-size:15px">receipt_long</span>Generate Receipt');
}
async function loadRGList(){
  try{
    const d=await api('GET','/api/tools/receipt/list');
    const c=g('rg-list');
    if(!d.receipts.length){c.innerHTML='<div style="text-align:center;color:var(--gray);padding:18px;background:var(--surface);border-radius:10px;border:1px solid var(--border)">No receipts yet</div>';return;}
    c.innerHTML=d.receipts.map(r=>{
      const p=PLATS.find(pl=>pl.k===r.platform)||{e:'🌐',n:r.platform,logo:'',bg:'#333'};
      const exp=new Date()>new Date(r.expiresAt);
      const es=exp?'<span style="color:var(--red);font-size:11px">Expired</span>':'<span style="color:var(--green);font-size:11px">Active until '+new Date(r.expiresAt).toLocaleDateString()+'</span>';
      const url=location.origin+'/view/'+r.slug;
      return \`<div class="gen-item"><div style="display:flex;align-items:center;gap:10px">
        <div style="width:32px;height:32px;border-radius:50%;background:\${p.bg};overflow:hidden;display:flex;align-items:center;justify-content:center;border:2px solid rgba(255,255,255,.1)"><img src="\${p.logo}" width="20" height="20" style="object-fit:contain" onerror="this.parentElement.innerHTML='\${p.e}'"/></div>
        <div><div class="gen-nm">\${p.n} \${r.tradeType} — \${r.asset}</div><div class="gen-mt">\${es} · \${r.days}d · $\${r.totalCost}</div></div></div>
        <div class="gen-acts"><button class="cpbtn" onclick="cp('\${url}')"><span class="ms material-symbols-outlined">content_copy</span>Copy</button><a class="vwbtn" href="/view/\${r.slug}" target="_blank"><span class="ms material-symbols-outlined">open_in_new</span>View</a></div></div>\`;
    }).join('');
  }catch(e){}
}

// ── TOOL 3: CRYPTO RECEIPT ────────────────────────────────────
async function genCR(){
  const brand=g('cr-brand').value,amt=g('cr-amt').value,addr=g('cr-addr').value.trim(),txid=g('cr-txid').value.trim(),status=g('cr-status').value,dt=g('cr-dt').value,coin=g('cr-coin').value,net=g('cr-net').value,days=g('cr-ds').value;
  if(!brand){toast('Select a brand','error');return;}
  if(!amt){toast('Enter amount','error');return;}
  if(!addr){toast('Enter address or account','error');return;}
  setLoad('cr-btn',true);
  try{ const r=await api('POST','/api/tools/crypto-receipt/generate',{brand,receiptType:crType,coin,network:net,amount:amt,address:addr,txid,status,dateTime:dt,days}); CU.balance=r.newBalance; updUI(r.newBalance); toast('Crypto receipt generated! Cost: $'+r.cost,'success'); loadCRList(); }
  catch(ex){ toast(ex.message,'error'); }
  setLoad('cr-btn',false,'<span class="material-symbols-outlined ms" style="font-size:15px">receipt</span>Generate Crypto Receipt');
}
async function loadCRList(){
  try{
    const d=await api('GET','/api/tools/crypto-receipt/list');
    const c=g('cr-list');
    if(!d.receipts.length){c.innerHTML='<div style="text-align:center;color:var(--gray);padding:18px;background:var(--surface);border-radius:10px;border:1px solid var(--border)">No crypto receipts yet</div>';return;}
    c.innerHTML=d.receipts.map(r=>{
      const exp=new Date()>new Date(r.expiresAt);
      const es=exp?'<span style="color:var(--red);font-size:11px">Expired</span>':'<span style="color:var(--green);font-size:11px">Active until '+new Date(r.expiresAt).toLocaleDateString()+'</span>';
      const url=location.origin+'/view/'+r.slug;
      const bdata=CR_BRANDS[r.receiptType==='bank'?'bank':'crypto'].find(b=>b.k===r.brand)||{logo:'',k:r.brand};
      return \`<div class="gen-item"><div style="display:flex;align-items:center;gap:10px">
        <div style="width:32px;height:32px;border-radius:50%;background:#1a1a1a;overflow:hidden;display:flex;align-items:center;justify-content:center;border:2px solid rgba(255,255,255,.1)"><img src="\${bdata.logo}" width="20" height="20" style="object-fit:contain" onerror="this.style.display='none'"/></div>
        <div><div class="gen-nm">\${r.brand} \${r.coin||''} Receipt — \${r.status}</div><div class="gen-mt">\${es} · \${r.days}d · $\${r.totalCost}</div></div></div>
        <div class="gen-acts"><button class="cpbtn" onclick="cp('\${url}')"><span class="ms material-symbols-outlined">content_copy</span>Copy</button><a class="vwbtn" href="/view/\${r.slug}" target="_blank"><span class="ms material-symbols-outlined">open_in_new</span>View</a></div></div>\`;
    }).join('');
  }catch(e){}
}

// ── DEPOSIT — FIXED PAYSTACK CALLBACK BUG ─────────────────────
function selDep(a){ g('dep-amt').value=a; document.querySelectorAll('.dchip').forEach(c=>c.classList.toggle('on',c.textContent==='$'+a)); }
function doDeposit(){
  const amount=parseFloat(g('dep-amt').value);
  if(!amount||amount<5){toast('Minimum deposit is $5','error');return;}
  if(!CU){toast('Please log in first','error');return;}
  setLoad('dep-btn',true);
  // FIX: use regular function (not async) for Paystack callbacks
  const handler=PaystackPop.setup({
    key:PAYSTACK_KEY,
    email:CU.email,
    amount:Math.round(amount*100),
    currency:'NGN',
    ref:'TV'+Date.now(),
    metadata:{userId:CU.id,depositAmountUSD:amount},
    onClose:function(){
      toast('Payment window closed','warn');
      setLoad('dep-btn',false,'<span class="material-symbols-outlined ms" style="font-size:15px">payments</span>Pay with Paystack');
    },
    callback:function(response){
      // FIX: don't use async here — call a separate async function instead
      handlePaystackCallback(response,amount);
    }
  });
  handler.openIframe();
}
function handlePaystackCallback(response,amount){
  api('POST','/api/payment/verify',{reference:response.reference})
    .then(function(r){
      CU.balance=r.balance;
      updUI(r.balance);
      toast('$'+amount+' added to wallet! 🎉','success');
      loadDash();
      showPanel('home');
    })
    .catch(function(ex){
      toast('Verification failed: '+ex.message,'error');
    })
    .finally(function(){
      setLoad('dep-btn',false,'<span class="material-symbols-outlined ms" style="font-size:15px">payments</span>Pay with Paystack');
    });
}
async function verifyPay(ref){
  try{ const r=await api('POST','/api/payment/verify',{reference:ref}); CU.balance=r.balance; updUI(r.balance); toast('Payment verified! $'+r.amount+' added','success'); await loadDash(); showPanel('home'); }catch(e){}
}

// ── ADMIN ─────────────────────────────────────────────────────
async function loadAdmin(){
  try{
    const d=await api('GET','/api/admin/stats');
    g('ad-users').textContent=d.users;
    g('ad-dep').textContent='$'+d.totalDeposits.toFixed(2);
    g('ad-rev').textContent='$'+d.toolRevenue.toFixed(2);
    g('ad-items').textContent=d.receipts+d.sites;
    const tb=g('ad-users-tbl');
    if(!d.recentUsers.length){tb.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--gray);padding:20px">No users yet</td></tr>';return;}
    tb.innerHTML=d.recentUsers.map(u=>\`<tr><td style="font-weight:500">\${u.name}</td><td style="color:var(--gray);font-size:12px">\${u.email}</td><td style="color:var(--green);font-weight:600">$\${u.balance.toFixed(2)}</td><td style="color:var(--gray);font-size:12px">\${new Date(u.createdAt).toLocaleDateString()}</td><td><button class="btn-ghost" onclick="g('ad-uid').value='\${u.id}'"><span class="ms material-symbols-outlined" style="font-size:13px">content_copy</span>Use ID</button></td></tr>\`).join('');
  }catch(e){ toast('Admin load failed: '+e.message,'error'); }
}
async function adminCredit(){
  const uid=g('ad-uid').value.trim(),amt=parseFloat(g('ad-amt').value),note=g('ad-note').value.trim();
  if(!uid||!amt){toast('User ID and amount required','error');return;}
  try{ await api('POST','/api/admin/credit',{userId:uid,amount:amt,note}); toast('Wallet credited successfully','success'); loadAdmin(); }
  catch(ex){ toast(ex.message,'error'); }
}

// ── HELPERS ───────────────────────────────────────────────────
function g(id){return document.getElementById(id);}
function toast(msg,type='success'){
  const el=g('toast'),ic=el.querySelector('.ms');
  el.className='show '+type; ic.textContent=type==='success'?'check_circle':type==='warn'?'warning':'error';
  g('tmsg').textContent=msg; clearTimeout(window._tt);
  window._tt=setTimeout(()=>el.classList.remove('show'),3500);
}
function setLoad(id,loading,html){
  const btn=g(id); if(!btn) return;
  const inn=btn.querySelector('.inn'); if(!inn){btn.disabled=loading;return;}
  if(loading){ if(!_bo[id])_bo[id]=inn.innerHTML; btn.disabled=true; inn.innerHTML='<span style="display:flex;gap:3px"><span class="bar" style="height:10px;margin:0 2px"></span><span class="bar" style="height:16px;margin:0 2px;animation-delay:.25s"></span><span class="bar" style="height:10px;margin:0 2px;animation-delay:.5s"></span></span>'; }
  else{ btn.disabled=false; inn.innerHTML=html||_bo[id]||inn.innerHTML; }
}
function cp(t){navigator.clipboard.writeText(t).then(()=>toast('Link copied!','success'));}
function togFaq(el){el.closest('.faq-item').classList.toggle('open');}

document.addEventListener('keydown',e=>{
  if(e.key!=='Enter') return;
  if(g('dash-pg').classList.contains('active')) return;
  if(g('auth-pg').classList.contains('active')){ if(g('lf').style.display!=='none') doLogin(); else doReg(); }
});

window.addEventListener('DOMContentLoaded',init);
<\/script></body></html>`;

// ─── VIEW HTML ────────────────────────────────────────────────
const VIEW_HTML=`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Loading…</title>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700;800;900&family=Inter:wght@300;400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
<style>
${CSS_COMMON}
body{overflow-y:auto}
#vldr{position:fixed;inset:0;background:var(--black);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:18px;z-index:999;transition:opacity .4s}
#vldr.gone{opacity:0;pointer-events:none}
.vldr-name{font-size:1.2rem;font-weight:800;letter-spacing:-.03em;color:var(--white)}
.vldr-name span{color:var(--yellow)}
.err-pg{min-height:100vh;display:none;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:40px;gap:14px}
.err-ico{font-size:60px}.err-ttl{font-size:1.4rem;font-weight:800;color:var(--white)}.err-sub{color:var(--gray);font-size:14px;max-width:340px}

/* ── SUPPORT SITE ── */
#sv{display:none}
.s-nav{height:62px;display:flex;align-items:center;justify-content:space-between;padding:0 28px;position:sticky;top:0;z-index:100;background:rgba(10,10,10,0.9);backdrop-filter:blur(20px);border-bottom:1px solid var(--border)}
.s-brand{display:flex;align-items:center;gap:10px}
.s-logo-wrap{width:32px;height:32px;border-radius:50%;overflow:hidden;display:flex;align-items:center;justify-content:center;border:2px solid rgba(255,255,255,.15)}
.s-logo-wrap img{width:22px;height:22px;object-fit:contain}
.s-bname{font-weight:800;font-size:.95rem;letter-spacing:-.02em;color:var(--white)}
.s-tag{font-size:9px;padding:1px 6px;border-radius:4px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;background:var(--yellow-dim);color:var(--yellow);border:1px solid var(--border-yellow);margin-left:4px}
.s-links{display:flex;gap:6px}
.s-link{padding:6px 12px;border-radius:7px;font-size:13px;font-weight:500;color:var(--gray);cursor:pointer;transition:.2s;background:none;border:none;font-family:var(--font)}
.s-link:hover{color:var(--white)}
.s-cta{padding:7px 16px;border-radius:8px;font-size:13px;font-weight:700;background:var(--yellow);color:var(--black);border:none;cursor:pointer;font-family:var(--font);transition:.2s}
.s-cta:hover{background:var(--yellow2)}
.exp-banner{background:rgba(245,197,24,.12);border-bottom:1px solid var(--border-yellow);padding:7px 18px;text-align:center;font-size:12px;font-weight:600;color:var(--yellow);display:none;align-items:center;justify-content:center;gap:5px}
.s-hero{padding:72px 28px;text-align:center;background:radial-gradient(ellipse at center top,rgba(245,197,24,0.07) 0%,transparent 60%),var(--black);border-bottom:1px solid var(--border)}
.s-badge{display:inline-flex;align-items:center;gap:6px;background:var(--yellow-dim);border:1px solid var(--border-yellow);border-radius:var(--radius-full);padding:4px 14px;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--yellow);margin-bottom:20px}
.s-bdot{width:5px;height:5px;border-radius:50%;background:var(--yellow);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.s-h1{font-size:clamp(2rem,5vw,3.2rem);font-weight:900;letter-spacing:-.04em;margin-bottom:14px;color:var(--white);line-height:1.1}
.s-sub{font-size:.95rem;color:var(--gray);max-width:500px;margin:0 auto 28px;line-height:1.7}
.s-acts{display:flex;justify-content:center;gap:10px;flex-wrap:wrap}
.s-btnp{padding:11px 24px;border-radius:10px;font-size:14px;font-weight:700;background:var(--yellow);color:var(--black);border:none;cursor:pointer;font-family:var(--font);display:inline-flex;align-items:center;gap:5px;transition:.2s}
.s-btnp:hover{background:var(--yellow2)}
.s-btns{padding:11px 24px;border-radius:10px;font-size:14px;font-weight:600;background:var(--surface);color:var(--white);border:1px solid var(--border);cursor:pointer;font-family:var(--font);display:inline-flex;align-items:center;gap:5px;transition:.2s}
.s-btns:hover{border-color:var(--yellow);color:var(--yellow)}
.s-sec{padding:52px 28px;max-width:1060px;margin:0 auto}
.s-sec-badge{display:inline-flex;align-items:center;gap:5px;background:var(--yellow-dim);border:1px solid var(--border-yellow);color:var(--yellow);padding:3px 10px;border-radius:var(--radius-full);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px}
.s-sec-h{font-size:1.5rem;font-weight:900;letter-spacing:-.03em;margin-bottom:7px;color:var(--white)}
.s-sec-d{color:var(--gray);font-size:14px;margin-bottom:28px}
.feat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.feat-card{padding:20px;border:1px solid var(--border);border-radius:var(--radius-xl);background:var(--surface)}
.feat-ic{width:36px;height:36px;border-radius:9px;background:var(--yellow-dim);display:flex;align-items:center;justify-content:center;margin-bottom:10px}
.feat-nm{font-weight:700;font-size:14px;margin-bottom:3px;color:var(--white)}.feat-d{font-size:13px;color:var(--gray);line-height:1.6}
.faq-wrap{max-width:680px;display:flex;flex-direction:column;gap:7px}
.faq-item{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);overflow:hidden;transition:.2s}
.faq-item:hover{border-color:var(--yellow)}
.faq-q{padding:14px 18px;display:flex;align-items:center;justify-content:space-between;cursor:pointer;font-weight:600;font-size:14px;color:var(--white);gap:10px}
.faq-ch{font-size:18px;color:var(--gray);transition:.2s;flex-shrink:0}
.faq-a{padding:0 18px;max-height:0;overflow:hidden;transition:.3s;font-size:13px;color:var(--gray);line-height:1.7}
.faq-item.open .faq-a{max-height:200px;padding:0 18px 14px}.faq-item.open .faq-ch{transform:rotate(180deg);color:var(--yellow)}
.s-footer{background:var(--dark);border-top:1px solid var(--border);padding:18px 28px;text-align:center;font-size:11px;color:var(--gray)}
.float-ct{position:fixed;bottom:24px;right:24px;z-index:1000}
.float-btn{display:flex;align-items:center;gap:7px;padding:13px 20px;border-radius:var(--radius-full);font-size:14px;font-weight:700;background:var(--yellow);color:var(--black);box-shadow:0 8px 24px rgba(245,197,24,.35);cursor:pointer;border:none;font-family:var(--font);text-decoration:none;transition:transform .2s,box-shadow .2s;animation:flin .5s .3s both}
.float-btn:hover{transform:translateY(-2px);box-shadow:0 12px 32px rgba(245,197,24,.45)}
@keyframes flin{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}

/* ── TRADING RECEIPT ── */
#rv{display:none}
.r-pg{min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:36px 16px;background:var(--black)}
.r-hdr{width:100%;max-width:460px;display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.r-brand{display:flex;align-items:center;gap:8px;font-weight:800;font-size:.95rem;color:var(--white)}
.r-sec{display:flex;align-items:center;gap:4px;font-size:11px;color:var(--gray)}
.r-card{width:100%;max-width:460px;background:var(--dark2);border:1px solid var(--border);border-radius:18px;overflow:hidden;box-shadow:var(--shadow)}
.r-ch{padding:20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px}
.r-plt-ic{width:44px;height:44px;border-radius:50%;display:flex;align-items:center;justify-content:center;overflow:hidden;flex-shrink:0}
.r-plt-ic img{width:30px;height:30px;object-fit:contain}
.r-plt-nm{font-weight:800;font-size:1rem;letter-spacing:-.02em;color:var(--white)}
.r-type-bdg{padding:2px 9px;border-radius:var(--radius-full);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-top:2px;display:inline-block}
.r-cb{padding:20px}
.r-amt-row{text-align:center;padding:18px 0;border-bottom:1px solid var(--border);margin-bottom:18px}
.r-amt-lbl{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--gray);margin-bottom:5px}
.r-amt-val{font-size:2.2rem;font-weight:900;letter-spacing:-.04em;color:var(--white)}
.r-amt-ast{font-size:13px;color:var(--gray);margin-top:3px}
.r-status{display:flex;align-items:center;gap:5px;padding:10px 14px;border-radius:8px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);margin:14px 0}
.r-sdot{width:7px;height:7px;border-radius:50%;background:var(--green);animation:pulse 2s infinite;flex-shrink:0}
.r-stxt{font-size:13px;font-weight:600;color:var(--green)}
.r-row{display:flex;align-items:flex-start;justify-content:space-between;padding:9px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:13px;gap:14px}
.r-row:last-child{border-bottom:none}
.r-rl{color:var(--gray);flex-shrink:0}.r-rv{font-weight:600;text-align:right;word-break:break-all;color:var(--white)}
.r-rv.mono{font-family:var(--font-mono);font-size:11px}
.r-ft{padding:14px 20px;background:rgba(0,0,0,.3);border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;font-size:11px;color:var(--gray)}
.r-actions{width:100%;max-width:460px;display:flex;gap:9px;margin-top:14px}
.r-act{flex:1;padding:11px;border-radius:10px;font-size:13px;font-weight:700;cursor:pointer;border:none;font-family:var(--font);display:flex;align-items:center;justify-content:center;gap:5px;transition:.2s}
.r-act.pri{background:var(--yellow);color:var(--black)}.r-act.sec{background:var(--surface);border:1px solid var(--border);color:var(--white)}
.r-act:hover{opacity:.85}
.r-note{margin-top:12px;font-size:11px;color:var(--gray);text-align:center}

/* ── CRYPTO RECEIPT ── */
#crv{display:none}
.cr-pg{min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:36px 16px;background:#07090d}
.cr-card{border-radius:22px;max-width:440px;width:100%;position:relative;overflow:hidden;box-shadow:0 32px 80px rgba(0,0,0,.8),0 0 0 1px rgba(255,255,255,.04)}
.cr-ribbon{position:absolute;top:14px;right:-30px;padding:5px 42px;font-size:9px;font-weight:800;letter-spacing:.12em;transform:rotate(45deg);pointer-events:none}
.cr-hdr{display:flex;justify-content:space-between;align-items:center;padding:22px 22px 16px}
.cr-logo-w{width:34px;height:34px;border-radius:50%;display:flex;align-items:center;justify-content:center;overflow:hidden;border:1px solid rgba(255,255,255,.1)}
.cr-logo-w img{width:22px;height:22px;object-fit:contain}
.cr-bname{font-weight:700;font-size:15px;color:#fff}.cr-bsub{font-size:10px;color:#6e7681}
.cr-date{font-size:10px;color:#6e7681;font-family:var(--font-mono)}
.cr-divider{border:none;border-top:1px solid rgba(255,255,255,.06);margin:0}
.cr-status-wrap{text-align:center;padding:26px 22px}
.cr-status-ic{width:70px;height:70px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 14px}
.cr-status-ic.completed{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.3)}
.cr-status-ic.pending{background:rgba(245,197,24,.12);border:1px solid rgba(245,197,24,.3);animation:pulse-s 2s ease-in-out infinite}
.cr-status-ic.canceled{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3)}
@keyframes pulse-s{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.65;transform:scale(1.05)}}
.cr-badge{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:999px;font-size:11px;font-weight:600;letter-spacing:.04em}
.cr-badge-dot{width:5px;height:5px;border-radius:50%;display:inline-block}
.cr-sdesc{font-size:12px;color:#6e7681;margin-top:6px}
.cr-amt-box{margin:0 22px 16px;border-radius:14px;padding:14px 16px}
.cr-amt-lbl{font-size:10px;color:#6e7681;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px}
.cr-amt-val{font-size:26px;font-weight:700;color:#fff}
.cr-amt-cur{font-size:13px;color:#6e7681;font-family:var(--font-mono);margin-top:2px}
.cr-details{margin:0 22px 16px;display:flex;flex-direction:column;gap:12px}
.cr-addr-lbl{font-size:10px;color:#6e7681;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px}
.cr-addr-val{background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:10px 12px;font-family:var(--font-mono);font-size:11px;color:#d4d8e2;word-break:break-all;line-height:1.6}
.cr-row{display:flex;justify-content:space-between;font-size:13px}
.cr-rl{color:#6e7681}.cr-rv{color:#d4d8e2;font-weight:500}
.cr-txid-lbl{font-size:10px;color:#6e7681;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px}
.cr-txid-val{font-family:var(--font-mono);font-size:10px;color:#6e7681;word-break:break-all;line-height:1.6}
.cr-footer{padding:12px 22px;border-top:1px solid rgba(255,255,255,.06);background:rgba(0,0,0,.2);display:flex;justify-content:space-between}
.cr-ft-txt{font-size:10px;color:#6e7681;max-width:280px}
.cr-actions{max-width:440px;width:100%;display:flex;gap:9px;margin-top:14px}
.cr-act{flex:1;padding:11px;border-radius:10px;font-size:13px;font-weight:700;cursor:pointer;border:none;font-family:var(--font);display:flex;align-items:center;justify-content:center;gap:5px;transition:.2s}
.cr-act:hover{opacity:.85}
.cr-note{margin-top:12px;font-size:11px;color:#6e7681;text-align:center}

/* BRANDED VIEW HEADER */
.view-brand-bar{background:var(--dark);border-bottom:1px solid var(--border);padding:10px 20px;display:flex;align-items:center;gap:8px}
.view-brand-bar-logo{width:28px;height:28px;border-radius:50%;overflow:hidden;display:flex;align-items:center;justify-content:center}
.view-brand-bar-logo img{width:20px;height:20px;object-fit:contain}
.view-brand-bar-name{font-size:12px;font-weight:700;color:var(--white)}
.view-brand-bar-powered{font-size:10px;color:var(--gray);margin-left:auto}
.view-brand-bar-powered span{color:var(--yellow);font-weight:600}

@media(max-width:600px){.s-hero{padding:44px 16px}.s-h1{font-size:1.8rem}.feat-grid{grid-template-columns:1fr}.s-nav{padding:0 14px}.s-links{display:none}}
</style>
</head>
<body>
<div id="vldr"><div class="vldr-name">Tooly<span>vans</span></div><div class="loader"><div class="bar"></div><div class="bar"></div><div class="bar"></div></div></div>
<div class="err-pg" id="ev" style="display:none"><div class="err-ico" id="eico">🔍</div><div class="err-ttl" id="ettl">Not Found</div><div class="err-sub" id="esub">This link does not exist or has been removed.</div><a href="/" style="margin-top:18px;padding:9px 22px;background:var(--yellow);color:var(--black);border-radius:8px;text-decoration:none;font-weight:700;font-size:13px">Back to Toolyvans</a></div>

<!-- SUPPORT SITE -->
<div id="sv">
  <div class="exp-banner" id="expb"><span class="material-symbols-outlined" style="font-size:14px">schedule</span><span id="exptxt">Expires soon</span></div>
  <nav class="s-nav">
    <div class="s-brand">
      <div class="s-logo-wrap" id="snav-logo"><span style="font-size:16px" id="snav-fb">🌐</span></div>
      <span id="snav-nm" class="s-bname">Platform</span>
      <span class="s-tag">Support</span>
    </div>
    <div class="s-links"><span class="s-link">Help</span><span class="s-link" onclick="document.getElementById('faq-sec').scrollIntoView({behavior:'smooth'})">FAQs</span><span class="s-link">Status</span></div>
    <button class="s-cta" id="snav-cta" onclick="trigContact()">Contact Support</button>
  </nav>
  <div class="s-hero" id="s-hero">
    <div class="s-badge"><span class="s-bdot"></span><span id="s-badge-tx">Support Online</span></div>
    <h1 class="s-h1" id="s-h1">How can we help you?</h1>
    <p class="s-sub" id="s-sub">Our support team is available 24/7 to assist you.</p>
    <div class="s-acts">
      <button class="s-btnp" id="s-cta-btn" onclick="trigContact()"><span class="material-symbols-outlined" style="font-size:15px" id="s-cta-ico">chat</span><span id="s-cta-tx">Contact Support</span></button>
      <button class="s-btns" onclick="document.getElementById('faq-sec').scrollIntoView({behavior:'smooth'})"><span class="material-symbols-outlined" style="font-size:15px">help_outline</span>Browse FAQs</button>
    </div>
  </div>
  <div class="s-sec">
    <div class="s-sec-badge"><span class="material-symbols-outlined" style="font-size:13px">verified</span>Verified Support</div>
    <h2 class="s-sec-h" id="feat-title">Official Support Channels</h2>
    <p class="s-sec-d">Get help from our verified team across multiple channels.</p>
    <div class="feat-grid">
      <div class="feat-card"><div class="feat-ic"><span class="material-symbols-outlined" style="font-size:18px;color:var(--yellow)">speed</span></div><div class="feat-nm">Fast Response</div><div class="feat-d">Average response time under 2 hours for all inquiries.</div></div>
      <div class="feat-card"><div class="feat-ic"><span class="material-symbols-outlined" style="font-size:18px;color:var(--yellow)">lock</span></div><div class="feat-nm">Secure & Verified</div><div class="feat-d">All agents are verified and follow strict security protocols.</div></div>
      <div class="feat-card"><div class="feat-ic"><span class="material-symbols-outlined" style="font-size:18px;color:var(--yellow)">schedule</span></div><div class="feat-nm">24/7 Available</div><div class="feat-d">Support available around the clock, every day.</div></div>
    </div>
  </div>
  <div style="background:var(--dark);border-top:1px solid var(--border);border-bottom:1px solid var(--border)">
    <div class="s-sec" id="faq-sec">
      <div class="s-sec-badge"><span class="material-symbols-outlined" style="font-size:13px">quiz</span>FAQs</div>
      <h2 class="s-sec-h">Common Questions</h2>
      <p class="s-sec-d">Quick answers to frequently asked questions.</p>
      <div class="faq-wrap" id="faq-list"></div>
    </div>
  </div>
  <div class="s-sec" style="text-align:center">
    <h2 class="s-sec-h" style="max-width:420px;margin:0 auto 10px">Still need help?</h2>
    <p class="s-sec-d" style="margin:0 auto 22px">Our support team is standing by for you.</p>
    <button class="s-btnp" onclick="trigContact()" style="margin:0 auto;display:inline-flex"><span class="material-symbols-outlined" style="font-size:15px" id="fct-ico">chat</span><span id="fct-tx">Contact Support Now</span></button>
  </div>
  <div class="s-footer"><span id="sfoo-nm">Platform</span> Support Center · Powered by <span style="color:var(--yellow);font-weight:700">Toolyvans</span></div>
  <div class="float-ct"><button class="float-btn" id="float-btn" onclick="trigContact()"><span class="material-symbols-outlined" id="float-ico" style="font-size:17px">chat</span><span id="float-tx">Get Support</span></button></div>
</div>

<!-- TRADING RECEIPT -->
<div id="rv">
  <!-- Branded view bar shows platform logo -->
  <div class="view-brand-bar" id="r-brand-bar">
    <div class="view-brand-bar-logo" id="r-bar-logo"></div>
    <span class="view-brand-bar-name" id="r-bar-name">Platform</span>
    <span class="view-brand-bar-powered">Powered by <span>Toolyvans</span></span>
  </div>
  <div class="r-pg" id="r-pg">
    <div class="r-hdr"><div class="r-brand" id="r-hdr-brand"></div><div class="r-sec"><span class="material-symbols-outlined" style="font-size:13px;color:var(--green)">verified_user</span>Secured</div></div>
    <div class="r-card">
      <div class="r-ch">
        <div class="r-plt-ic" id="r-plt-ic"></div>
        <div><div class="r-plt-nm" id="r-plt-nm">Platform</div><span class="r-type-bdg" id="r-type-bdg">BUY</span></div>
      </div>
      <div class="r-cb">
        <div class="r-amt-row"><div class="r-amt-lbl">Total Value</div><div class="r-amt-val" id="r-total">$0.00</div><div class="r-amt-ast" id="r-ast-info">0 BTC @ $0</div></div>
        <div class="r-status"><div class="r-sdot"></div><div class="r-stxt" id="r-stxt">Transaction Successful</div></div>
        <div class="r-row"><span class="r-rl">Transaction ID</span><span class="r-rv mono" id="r-txid">—</span></div>
        <div class="r-row"><span class="r-rl">Date & Time</span><span class="r-rv" id="r-date">—</span></div>
        <div class="r-row"><span class="r-rl">Asset</span><span class="r-rv" id="r-asset">—</span></div>
        <div class="r-row"><span class="r-rl">Amount</span><span class="r-rv" id="r-amount">—</span></div>
        <div class="r-row"><span class="r-rl">Price per Unit</span><span class="r-rv" id="r-price">—</span></div>
        <div class="r-row"><span class="r-rl">Fee</span><span class="r-rv" id="r-fee">—</span></div>
        <div class="r-row" id="r-wa-row" style="display:none"><span class="r-rl">Wallet</span><span class="r-rv mono" id="r-wa">—</span></div>
        <div class="r-row"><span class="r-rl">Platform</span><span class="r-rv" id="r-plt-row">—</span></div>
        <div class="r-row"><span class="r-rl">Status</span><span class="r-rv" style="color:var(--green);font-weight:700">✓ Confirmed</span></div>
      </div>
      <div class="r-ft"><span id="r-ft-plt">Platform Receipt</span><span id="r-ft-date">—</span></div>
    </div>
    <div class="r-actions">
      <button class="r-act pri" onclick="window.print()"><span class="material-symbols-outlined" style="font-size:15px">download</span>Download</button>
      <button class="r-act sec" onclick="navigator.clipboard.writeText(location.href).then(()=>alert('Link copied!'))"><span class="material-symbols-outlined" style="font-size:15px">share</span>Share</button>
    </div>
    <div class="r-note">Generated by <strong style="color:var(--yellow)">Toolyvans</strong> · Valid until <span id="r-exp">—</span></div>
  </div>
</div>

<!-- CRYPTO RECEIPT -->
<div id="crv">
  <div class="view-brand-bar" id="cr-brand-bar">
    <div class="view-brand-bar-logo" id="cr-bar-logo"></div>
    <span class="view-brand-bar-name" id="cr-bar-name">Brand</span>
    <span class="view-brand-bar-powered">Powered by <span>Toolyvans</span></span>
  </div>
  <div class="cr-pg">
    <div class="cr-card" id="cr-card">
      <div class="cr-ribbon" id="cr-ribbon">VERIFIED</div>
      <div class="cr-hdr">
        <div style="display:flex;align-items:center;gap:10px">
          <div class="cr-logo-w" id="cr-logo-w"><img id="cr-logo" src="" alt="" onerror="this.style.display='none'"/></div>
          <div><div class="cr-bname" id="cr-bname">Platform</div><div class="cr-bsub" id="cr-bsub">Exchange</div></div>
        </div>
        <span class="cr-date" id="cr-date">—</span>
      </div>
      <hr class="cr-divider"/>
      <div class="cr-status-wrap">
        <div class="cr-status-ic" id="cr-sic">
          <svg id="cr-svg" width="38" height="38" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>
        </div>
        <div class="cr-badge" id="cr-badge"><span class="cr-badge-dot" id="cr-bdot"></span><span id="cr-btxt">Completed</span></div>
        <p class="cr-sdesc" id="cr-sdesc">Transaction successful</p>
      </div>
      <div class="cr-amt-box" id="cr-amt-box">
        <div class="cr-amt-lbl">Amount</div>
        <div class="cr-amt-val" id="cr-amt-val">0.00</div>
        <div class="cr-amt-cur" id="cr-amt-cur">USDT</div>
      </div>
      <hr class="cr-divider"/>
      <div class="cr-details">
        <div><div class="cr-addr-lbl" id="cr-addr-lbl">Address</div><div class="cr-addr-val" id="cr-addr-val">—</div></div>
        <div class="cr-row"><span class="cr-rl">Method</span><span class="cr-rv" id="cr-method">—</span></div>
      </div>
      <hr class="cr-divider"/>
      <div style="padding:14px 22px"><div class="cr-txid-lbl" id="cr-tx-lbl">Transaction Hash</div><div class="cr-txid-val" id="cr-tx-val">—</div></div>
      <div class="cr-footer"><p class="cr-ft-txt">Private transaction receipt. Do not share with unauthorized parties.</p></div>
    </div>
    <div class="cr-actions">
      <button class="cr-act" id="cr-dl-btn" onclick="window.print()"><span class="material-symbols-outlined" style="font-size:15px">download</span>Download</button>
      <button class="cr-act" style="background:rgba(255,255,255,.06);color:#d4d8e2;border:1px solid rgba(255,255,255,.1)" onclick="navigator.clipboard.writeText(location.href).then(()=>alert('Link copied!'))"><span class="material-symbols-outlined" style="font-size:15px">share</span>Share</button>
    </div>
    <div class="cr-note">Generated by <strong style="color:var(--yellow)">Toolyvans</strong> · Valid until <span id="cr-exp">—</span></div>
  </div>
</div>

<script>
const PLAT_DATA={
  binance:{n:'Binance',logo:'https://bin.bnbstatic.com/static/images/common/favicon.ico',fb:'BNB',bg:'#181A20',accent:'#F3BA2F',dark:true,faq:[{q:'How do I reset my password?',a:'Visit the Binance login page, click Forgot Password, enter your email and follow the reset link.'},{q:'Why is my withdrawal delayed?',a:'Withdrawals may be delayed due to security reviews or network congestion. Typically resolved within 24 hours.'},{q:'How do I complete KYC?',a:'Go to Account > Identification and upload your ID and selfie. Usually completes within 30 minutes.'},{q:'What are the trading fees?',a:'Spot trading fees start at 0.1%. Use BNB to pay fees for a 25% discount.'},{q:'How do I enable 2FA?',a:'Go to Security settings and enable Google Authenticator or SMS 2FA.'}]},
  bybit:{n:'Bybit',logo:'https://www.bybit.com/favicon.ico',fb:'BBT',bg:'#1C1C1E',accent:'#F7A600',dark:true,faq:[{q:'How do I deposit to Bybit?',a:'Navigate to Assets > Deposit, select your coin and copy the deposit address.'},{q:'What leverage is available?',a:'Bybit offers up to 100x leverage on derivatives. Set leverage in the trading interface.'},{q:'How do I withdraw?',a:'Go to Assets > Withdrawal, select coin and network, enter wallet address and confirm.'},{q:'What is the funding rate?',a:'Funding is exchanged between long and short positions every 8 hours.'},{q:'How can I contact support?',a:'Use live chat at the bottom right of this page or submit a support ticket.'}]},
  coinbase:{n:'Coinbase',logo:'https://www.coinbase.com/favicon.ico',fb:'CB',bg:'#0052FF',accent:'#0052FF',dark:true,faq:[{q:'How do I buy crypto?',a:'Click Buy/Sell, select your crypto, choose payment method, enter amount and confirm.'},{q:'How long do deposits take?',a:'Bank transfers take 3-5 business days. Debit card purchases are instant.'},{q:'What is Coinbase One?',a:'Coinbase One offers zero trading fees, priority support, and enhanced account protections.'},{q:'How do I report unauthorized activity?',a:'Immediately lock your account, change your password, and contact our support team urgently.'},{q:'Are my funds insured?',a:'USD balances are FDIC insured up to $250,000. Crypto is stored in cold storage.'}]},
  metamask:{n:'MetaMask',logo:'https://raw.githubusercontent.com/MetaMask/brand-resources/master/SVG/SVG_MetaMask_Icon_Color.svg',fb:'MM',bg:'#F6851B',accent:'#E8821A',dark:false,faq:[{q:'I forgot my password. What do I do?',a:'Restore your wallet using your 12-word Secret Recovery Phrase. Never share this phrase with anyone.'},{q:'Why is my transaction pending?',a:'Low gas fees can cause delays. You can speed up or cancel pending transactions in MetaMask.'},{q:'How do I add a custom network?',a:'Go to Settings > Networks > Add Network and enter the RPC URL, Chain ID and token symbol.'},{q:'What is a gas fee?',a:'Gas fees are payments to validators for processing transactions. They vary with network congestion.'},{q:'How do I import a wallet?',a:'Click account icon > Import Account and paste your private key or use your recovery phrase.'}]},
  trustwallet:{n:'Trust Wallet',logo:'https://trustwallet.com/assets/images/media/assets/TWT.png',fb:'TW',bg:'#3375BB',accent:'#3375BB',dark:true,faq:[{q:'How do I backup my wallet?',a:'Go to Settings > Wallets, select your wallet and tap Backup to see your 12-word recovery phrase.'},{q:'Can I use Trust Wallet on multiple devices?',a:'Yes. Import your wallet on the new device using your recovery phrase.'},{q:'Why is my balance not showing?',a:'Try refreshing the app and check you are on the correct blockchain network for your assets.'},{q:'How do I buy crypto?',a:'Tap Buy on the home screen, select your crypto and payment method.'},{q:'Is Trust Wallet safe?',a:'Trust Wallet is non-custodial — only you control your private keys and funds.'}]},
  robinhood:{n:'Robinhood',logo:'https://robinhood.com/favicon.ico',fb:'RH',bg:'#00C805',accent:'#00C805',dark:false,faq:[{q:'How do I transfer funds?',a:'Go to Account > Transfers > Transfer to Robinhood. Bank transfers take 3-5 business days.'},{q:'What crypto can I trade?',a:'Robinhood supports Bitcoin, Ethereum, Dogecoin, Shiba Inu and several other cryptocurrencies.'},{q:'How do I sell stocks or crypto?',a:'Tap on the asset, select Sell, enter the amount, review and confirm your order.'},{q:'What is Robinhood Gold?',a:'Robinhood Gold offers margin investing, larger instant deposits, and professional market data.'},{q:'How are dividends handled?',a:'Cash dividends are automatically deposited to your account on the payment date.'}]},
  phantom:{n:'Phantom',logo:'https://phantom.app/img/phantom-logo.png',fb:'PH',bg:'#9945FF',accent:'#9945FF',dark:true,faq:[{q:'How do I create a Phantom wallet?',a:'Download the Phantom extension or app, click Create New Wallet and safely store your recovery phrase.'},{q:'How do I buy SOL?',a:'Tap Buy in your wallet and use MoonPay or another supported provider to purchase SOL directly.'},{q:'Why is my NFT not showing?',a:'Try refreshing or switching networks. Some NFTs may need to be added manually in the NFT tab.'},{q:'How do I swap tokens?',a:'Open Phantom, tap the Swap icon, select your tokens, enter amount, review and confirm.'},{q:'What is Solana?',a:'Solana is a high-performance blockchain supporting fast, low-cost transactions. Phantom is the leading Solana wallet.'}]},
  kraken:{n:'Kraken',logo:'https://www.kraken.com/favicon.ico',fb:'KRK',bg:'#5741D9',accent:'#5741D9',dark:true,faq:[{q:'How do I verify my account?',a:'Go to Account Settings > Verification and upload the required documents for your verification tier.'},{q:'What are Kraken trading fees?',a:'Maker fees start at 0.16% and taker fees at 0.26%. Fees decrease with higher trading volume.'},{q:'How do I enable staking?',a:'Go to the Staking section, select your asset and follow the steps to start earning rewards.'},{q:'What is Kraken Pro?',a:'Kraken Pro is the advanced trading interface with charting tools, order types and lower fees.'},{q:'How secure is Kraken?',a:'Kraken uses 95% cold storage, 2FA, master key and PGP email encryption.'}]},
  kucoin:{n:'KuCoin',logo:'https://www.kucoin.com/favicon.ico',fb:'KCS',bg:'#23AF91',accent:'#23AF91',dark:true,faq:[{q:'How do I deposit on KuCoin?',a:'Go to Assets > Deposit, select your coin and network, and copy the deposit address.'},{q:'What is KCS?',a:'KCS is KuCoin native token offering fee discounts, daily bonuses and voting rights.'},{q:'How do I trade futures?',a:'Switch to the Futures tab, select your trading pair, set leverage and place your order.'},{q:'What are KuCoin trading fees?',a:'Spot trading fees are 0.1%. Holding 1,000+ KCS gives a 20% fee discount.'},{q:'How does P2P trading work?',a:'P2P lets you buy/sell directly with other users using bank transfers and local payment methods.'}]},
  okx:{n:'OKX',logo:'https://static.okx.com/cdn/assets/imgs/221/9E073F600D8C8D77.png',fb:'OKX',bg:'#000000',accent:'#ffffff',dark:true,faq:[{q:'How do I create an OKX account?',a:'Download the OKX app or visit okx.com, click Sign Up and complete registration with your email.'},{q:'What trading options are available?',a:'OKX offers spot, margin, futures, perpetual swaps and options trading across hundreds of pairs.'},{q:'How do I withdraw funds?',a:'Go to Assets > Withdraw, select coin and network, enter wallet address and confirm.'},{q:'What is the OKB token?',a:'OKB is OKX utility token providing trading fee discounts and access to token sales.'},{q:'How do I set up API trading?',a:'Go to Account > API and create an API key with the required permissions. Never share your secret key.'}]}
};

const CR_BRAND_CFG={
  'Binance':{logo:'https://bin.bnbstatic.com/static/images/common/favicon.ico',accent:'#FCD535',cardBg:'#181a20',ribbon:'VERIFIED',ribbonBg:'#FCD535',ribbonColor:'#000',sub:'Crypto Exchange',addrLbl:'Wallet Address',txLbl:'Transaction Hash'},
  'Coinbase':{logo:'https://www.coinbase.com/favicon.ico',accent:'#0052FF',cardBg:'#0a0d14',ribbon:'VERIFIED',ribbonBg:'#0052FF',ribbonColor:'#fff',sub:'Crypto Exchange',addrLbl:'Wallet Address',txLbl:'Transaction ID'},
  'OKX':{logo:'https://static.okx.com/cdn/assets/imgs/221/9E073F600D8C8D77.png',accent:'#ffffff',cardBg:'#0d0d0d',ribbon:'VERIFIED',ribbonBg:'#fff',ribbonColor:'#000',sub:'Crypto Exchange',addrLbl:'Wallet Address',txLbl:'Transaction Hash'},
  'Kraken':{logo:'https://www.kraken.com/favicon.ico',accent:'#5741d9',cardBg:'#100f1c',ribbon:'VERIFIED',ribbonBg:'#5741d9',ribbonColor:'#fff',sub:'Crypto Exchange',addrLbl:'Wallet Address',txLbl:'Transaction ID'},
  'Bybit':{logo:'https://www.bybit.com/favicon.ico',accent:'#F7A600',cardBg:'#13110a',ribbon:'VERIFIED',ribbonBg:'#F7A600',ribbonColor:'#000',sub:'Crypto Exchange',addrLbl:'Wallet Address',txLbl:'Transaction Hash'},
  'KuCoin':{logo:'https://www.kucoin.com/favicon.ico',accent:'#23AF91',cardBg:'#091410',ribbon:'VERIFIED',ribbonBg:'#23AF91',ribbonColor:'#fff',sub:'Crypto Exchange',addrLbl:'Wallet Address',txLbl:'Transaction Hash'},
  'Cash App':{logo:'https://cash.app/favicon.ico',accent:'#00D632',cardBg:'#0a1208',ribbon:'SUCCESS',ribbonBg:'#00D632',ribbonColor:'#fff',sub:'Cash App Pay',addrLbl:'Cashtag / $',txLbl:'Web Receipt'},
  'Zelle':{logo:'https://www.zellepay.com/favicon.ico',accent:'#6D1ED4',cardBg:'#0e0814',ribbon:'SENT',ribbonBg:'#6D1ED4',ribbonColor:'#fff',sub:'Zelle Network',addrLbl:'Email / Phone',txLbl:'Reference Number'},
  'PayPal':{logo:'https://www.paypal.com/favicon.ico',accent:'#0070E0',cardBg:'#080d14',ribbon:'SENT',ribbonBg:'#0070E0',ribbonColor:'#fff',sub:'PayPal Transfer',addrLbl:'Email / Account',txLbl:'Transaction ID'},
  'Chase':{logo:'https://www.chase.com/favicon.ico',accent:'#117ACA',cardBg:'#080f16',ribbon:'SENT',ribbonBg:'#117ACA',ribbonColor:'#fff',sub:'J.P. Morgan Chase',addrLbl:'Recipient Account',txLbl:'Confirmation Number'},
  'Bank of America':{logo:'https://www.bankofamerica.com/favicon.ico',accent:'#E31837',cardBg:'#130308',ribbon:'SENT',ribbonBg:'#E31837',ribbonColor:'#fff',sub:'Bank of America',addrLbl:'Recipient Account',txLbl:'Confirmation Number'},
  'Wells Fargo':{logo:'https://www.wellsfargo.com/favicon.ico',accent:'#CC0000',cardBg:'#130000',ribbon:'SENT',ribbonBg:'#CC0000',ribbonColor:'#fff',sub:'Wells Fargo Bank',addrLbl:'Recipient Account',txLbl:'Confirmation Number'}
};

function g(id){return document.getElementById(id);}
function rgba(hex,a){const r=parseInt(hex.slice(1,3),16),gr=parseInt(hex.slice(3,5),16),b=parseInt(hex.slice(5,7),16);return isNaN(r)?'rgba(245,197,24,'+a+')':'rgba('+r+','+gr+','+b+','+a+')';}

async function init(){
  const slug=location.pathname.replace(/^\\/view\\//,'').replace(/^\\/+|\\/+$/g,'');
  if(!slug){showErr('not_found');return;}
  try{
    const r=await fetch('/api/view/'+slug);
    const d=await r.json();
    if(!r.ok){showErr(d.error,d.message);return;}
    if(d.type==='support-site') renderSS(d.data);
    else if(d.type==='receipt') renderReceipt(d.data);
    else if(d.type==='crypto-receipt') renderCR(d.data);
    else showErr('not_found');
  }catch(e){showErr('not_found','Could not load content.');}
  g('vldr').classList.add('gone');
}

function showErr(type,msg){
  g('vldr').classList.add('gone');
  const ev=g('ev'); ev.style.display='flex';
  if(type==='expired'){g('eico').textContent='⏳';g('ettl').textContent='Link Expired';g('esub').textContent=msg||'This content has expired.';}
  else{g('eico').textContent='🔍';g('ettl').textContent='Not Found';g('esub').textContent=msg||'This link does not exist.';}
}

function renderSS(site){
  const p=PLAT_DATA[site.platform]||{n:site.platform,logo:'',fb:'🌐',bg:'#1a1a1a',accent:'#F5C518',dark:true,faq:[]};
  document.title=p.n+' Support Center';
  // Logo in nav — circular with real logo
  const logoWrap=g('snav-logo');
  logoWrap.style.background=p.bg;
  logoWrap.innerHTML='<img src="'+p.logo+'" width="20" height="20" style="object-fit:contain" onerror="this.parentElement.innerHTML=\\'<span style=font-size:14px>'+p.fb+'</span>\\'" />';
  g('snav-nm').textContent=p.n;
  g('snav-cta').style.background=p.accent;
  g('snav-cta').style.color=p.dark&&p.accent!=='#ffffff'?'#000':'#000';
  g('s-badge-tx').textContent=p.n+' Support Online';
  g('s-h1').textContent='How can we help you?';
  g('s-sub').textContent='Welcome to '+p.n+' Support Center. Our team is available 24/7.';
  const icoM={email:'mail',whatsapp:'chat',telegram:'send',chatbot:'smart_toy'};
  const txM={email:'Email Support',whatsapp:'WhatsApp Us',telegram:'Telegram Chat',chatbot:'Live Chat'};
  const ico=icoM[site.contactMethod]||'chat',ctaTx=txM[site.contactMethod]||'Contact Support';
  [g('s-cta-ico'),g('fct-ico'),g('float-ico')].forEach(el=>{if(el)el.textContent=ico;});
  [g('s-cta-tx'),g('fct-tx'),g('float-tx')].forEach(el=>{if(el)el.textContent=ctaTx;});
  g('s-cta-btn').style.background=p.accent; g('s-cta-btn').style.color='#000';
  g('float-btn').style.background=p.accent; g('float-btn').style.color='#000';
  window._sc={method:site.contactMethod,value:site.contactValue,chatbot:site.chatbotCode};
  g('faq-list').innerHTML=p.faq.map((f,i)=>'<div class="faq-item"><div class="faq-q" onclick="togFaq(this)"><span>'+f.q+'</span><span class="faq-ch material-symbols-outlined">expand_more</span></div><div class="faq-a">'+f.a+'</div></div>').join('');
  g('sfoo-nm').textContent=p.n;
  const dl=Math.ceil((new Date(site.expiresAt)-new Date())/86400000);
  if(dl<=3&&dl>0){const b=g('expb');b.style.display='flex';g('exptxt').textContent='This site expires in '+dl+' day'+(dl!==1?'s':'');}
  if(site.contactMethod==='chatbot'&&site.chatbotCode){const el=document.createElement('div');el.innerHTML=site.chatbotCode;document.body.appendChild(el);}
  g('sv').style.display='block';
}

function trigContact(){
  const c=window._sc; if(!c) return;
  if(c.method==='email') location.href='mailto:'+c.value;
  else if(c.method==='whatsapp') window.open('https://wa.me/'+c.value.replace(/\\D/g,''),'_blank');
  else if(c.method==='telegram') window.open(c.value.startsWith('http')?c.value:'https://t.me/'+c.value.replace('@',''),'_blank');
  else alert('Live chat is active. Look for the chat widget on this page.');
}
function togFaq(el){el.closest('.faq-item').classList.toggle('open');}

function renderReceipt(r){
  const p=PLAT_DATA[r.platform]||{n:r.platform,logo:'',fb:'🌐',bg:'#1a1a1a',accent:'#F5C518'};
  document.title=p.n+' '+r.tradeType+' Receipt — '+r.asset;
  // Branded top bar
  const barLogo=g('r-bar-logo');
  barLogo.style.background=p.bg;
  barLogo.innerHTML='<img src="'+p.logo+'" width="18" height="18" style="object-fit:contain;border-radius:0" onerror="this.parentElement.innerHTML=\\'<span style=font-size:12px>'+p.fb+'</span>\\'"/>';
  g('r-bar-name').textContent=p.n+' · '+r.tradeType+' Receipt';
  // Receipt card platform icon — circular
  const ic=g('r-plt-ic');
  ic.style.background=p.bg; ic.style.border='2px solid rgba(255,255,255,0.1)';
  ic.innerHTML='<img src="'+p.logo+'" width="28" height="28" style="object-fit:contain" onerror="this.parentElement.innerHTML=\\'<span style=font-size:18px>'+p.fb+'</span>\\'"/>';
  g('r-hdr-brand').innerHTML='<div style="width:24px;height:24px;border-radius:50%;background:'+p.bg+';overflow:hidden;display:flex;align-items:center;justify-content:center;border:2px solid rgba(255,255,255,.1)"><img src="'+p.logo+'" width="16" height="16" style="object-fit:contain" onerror="this.parentElement.innerHTML=\\'<span>'+p.fb+'</span>\\'" /></div><span>'+p.n+'</span>';
  g('r-plt-nm').textContent=p.n;
  const tc={BUY:'var(--green)',SELL:'var(--red)',DEPOSIT:'var(--blue)',WITHDRAWAL:'#ff9500',TRANSFER:'#9945FF'};
  const bdg=g('r-type-bdg'); bdg.textContent=r.tradeType; bdg.style.background=rgba(p.accent,.12); bdg.style.color=p.accent;
  g('r-total').textContent='$'+parseFloat(r.totalValue).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
  g('r-ast-info').textContent=parseFloat(r.amount).toFixed(6)+' '+r.asset+' @ $'+parseFloat(r.price).toLocaleString();
  g('r-stxt').textContent=r.tradeType+' Successful';
  g('r-txid').textContent=r.txId;
  const d=new Date(r.date);
  g('r-date').textContent=d.toLocaleDateString('en-US',{weekday:'long',year:'numeric',month:'long',day:'numeric'})+' · '+d.toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'});
  g('r-asset').textContent=r.asset;
  g('r-amount').textContent=parseFloat(r.amount).toFixed(8)+' '+r.asset;
  g('r-price').textContent='$'+parseFloat(r.price).toLocaleString('en-US',{minimumFractionDigits:2});
  g('r-fee').textContent='$'+parseFloat(r.fee||0).toFixed(2);
  g('r-plt-row').textContent=p.n;
  if(r.walletAddress){g('r-wa-row').style.display='flex';g('r-wa').textContent=r.walletAddress;}
  g('r-ft-plt').textContent=p.n+' Receipt'; g('r-ft-date').textContent=new Date(r.createdAt).toLocaleDateString();
  g('r-exp').textContent=new Date(r.expiresAt).toLocaleDateString();
  g('rv').style.display='block';
}

function renderCR(r){
  const cfg=CR_BRAND_CFG[r.brand]||{logo:'',accent:'#F5C518',cardBg:'#1a1a1a',ribbon:'VERIFIED',ribbonBg:'#F5C518',ribbonColor:'#000',sub:'Exchange',addrLbl:'Address',txLbl:'Transaction Hash'};
  document.title=r.brand+' '+r.coin+' Receipt — '+r.status;
  // Branded top bar
  const barLogo=g('cr-bar-logo');
  barLogo.style.background=cfg.accent+'22';
  barLogo.innerHTML='<img src="'+cfg.logo+'" width="18" height="18" style="object-fit:contain" onerror="this.style.display=\\'none\\'"/>';
  g('cr-bar-name').textContent=r.brand+' Receipt';
  const card=g('cr-card'); card.style.background=cfg.cardBg;
  const rib=g('cr-ribbon'); rib.textContent=cfg.ribbon; rib.style.background=cfg.ribbonBg; rib.style.color=cfg.ribbonColor;
  const lw=g('cr-logo-w'); lw.style.background=cfg.accent+'22';
  g('cr-logo').src=cfg.logo; g('cr-bname').textContent=r.brand; g('cr-bsub').textContent=cfg.sub;
  const dt=r.dateTime?new Date(r.dateTime).toLocaleString('en-US',{dateStyle:'medium',timeStyle:'short'}):new Date(r.createdAt).toLocaleString('en-US',{dateStyle:'medium',timeStyle:'short'});
  g('cr-date').textContent=dt;
  const sic=g('cr-sic'),svg=g('cr-svg'),bdg=g('cr-badge'),bdot=g('cr-bdot'),btxt=g('cr-btxt'),sdesc=g('cr-sdesc');
  sic.className='cr-status-ic '+r.status;
  if(r.status==='completed'){svg.setAttribute('stroke',cfg.accent);svg.innerHTML='<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>';bdg.style.background=cfg.accent+'22';bdg.style.color=cfg.accent;bdot.style.background=cfg.accent;btxt.textContent='Completed';sdesc.textContent='Transaction successful — funds on the way';}
  else if(r.status==='canceled'){svg.setAttribute('stroke','#ef4444');svg.innerHTML='<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>';bdg.style.background='#ef444422';bdg.style.color='#ef4444';bdot.style.background='#ef4444';btxt.textContent='Canceled';sdesc.textContent='Transaction declined or canceled';}
  else{svg.setAttribute('stroke',cfg.accent);svg.innerHTML='<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>';bdg.style.background=cfg.accent+'22';bdg.style.color=cfg.accent;bdot.style.background=cfg.accent;btxt.textContent='Pending';sdesc.textContent='Processing your transaction…';}
  const ab=g('cr-amt-box'); ab.style.background=cfg.accent+'12'; ab.style.borderColor=cfg.accent+'33';
  g('cr-amt-val').textContent=r.amount; g('cr-amt-cur').textContent=r.coin||(r.receiptType==='bank'?'USD':'USDT');
  g('cr-addr-lbl').textContent=cfg.addrLbl; g('cr-addr-val').textContent=r.address;
  g('cr-method').textContent=r.network||(r.receiptType==='bank'?'Bank Transfer':'TRC20');
  g('cr-tx-lbl').textContent=cfg.txLbl; g('cr-tx-val').textContent=r.txid||'—';
  g('cr-exp').textContent=new Date(r.expiresAt).toLocaleDateString();
  const dlBtn=g('cr-dl-btn'); dlBtn.style.background=cfg.accent; dlBtn.style.color=cfg.ribbonColor;
  g('crv').style.display='block';
}

init();
<\/script>
</body></html>`;

// ── HTML ROUTES ───────────────────────────────────────────────
app.get('/view/*',(_req,res)=>{res.setHeader('Content-Type','text/html;charset=utf-8');res.send(VIEW_HTML);});
app.get('*',(_req,res)=>{res.setHeader('Content-Type','text/html;charset=utf-8');res.send(DASHBOARD_HTML);});

// ── START ─────────────────────────────────────────────────────
if(!process.env.VERCEL){
  const PORT=process.env.PORT||3000;
  app.listen(PORT,()=>console.log('🚀  Toolyvans → http://localhost:'+PORT));
}
module.exports=app;
