const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const digits = n => new Intl.NumberFormat('fa-IR').format(n || 0);
const fmtSize = n => n < 1024 ? `${digits(n)} بایت` : n < 1048576 ? `${digits((n/1024).toFixed(1))} کیلوبایت` : `${digits((n/1048576).toFixed(1))} مگابایت`;
const fmtDate = value => new Intl.DateTimeFormat('fa-IR', { year:'numeric', month:'short', day:'numeric' }).format(new Date(value));
let docs = [], feedback = [], pendingFeedback = null, toastTimer, csrfToken = null, currentUser = null, authMode = 'login', authStep = 'phone', authChallenge = null, googlePhoneFlow = false;
const state = { currentQuestion:'', busy:false };
async function api(url, options={}) {
  const method = (options.method || 'GET').toUpperCase();
  const securityHeaders = csrfToken && !['GET','HEAD','OPTIONS'].includes(method) ? {'X-CSRF-Token': csrfToken} : {};
  let previewBearer={};try{const token=sessionStorage.getItem('hy_preview_token');if(token)previewBearer={Authorization:`Bearer ${token}`};}catch{}
  const res = await fetch(url, { credentials: 'include', ...options, headers: { ...(options.body ? {'Content-Type':'application/json'} : {}), ...previewBearer, ...securityHeaders, ...(options.headers||{}) } });
  const data = await res.json().catch(() => ({}));
  if((res.status===401||['ACCOUNT_PENDING','ACCOUNT_DISABLED'].includes(data.code))&&!url.startsWith('/api/auth/'))forceLock(data.error);
  if (!res.ok) throw new Error(data.error || 'ارتباط با سامانه انجام نشد.'); return data;
}
function toast(text) { const el=$('#toast'); el.textContent=text; el.classList.add('show'); clearTimeout(toastTimer); toastTimer=setTimeout(()=>el.classList.remove('show'),2600); }
function navigate(page) {
  if (!$('#page-'+page) || (page==='users' && currentUser?.role!=='system_admin')) page='dashboard';
  $$('.page').forEach(p=>p.classList.toggle('active',p.id==='page-'+page));
  $$('.nav-item').forEach(a=>a.classList.toggle('active',a.dataset.page===page));
  const labels={dashboard:'نمای کلی',chat:'گفت‌وگو با اسناد',documents:'کتابخانه اسناد',learning:'یادگیری و بازخورد',users:'کاربران و دسترسی‌ها'};
  $('#crumb').textContent=labels[page]; $('#sidebar').classList.remove('open');
  if (location.hash !== '#'+page) history.replaceState(null,'','#'+page);
  if(page==='chat') updateChatSources(); if(page==='users') loadUsers();
}
function renderDocs() {
  const needle=($('#docSearch')?.value||'').trim().toLocaleLowerCase('fa'); const filtered=docs.filter(d=>d.name.toLocaleLowerCase('fa').includes(needle));
  $('#statDocs').textContent=digits(docs.length); $('#navDocCount').textContent=digits(docs.length); $('#docTotal').textContent=`${digits(filtered.length)} سند`; $('#tableCount').textContent=`${digits(filtered.length)} مورد`;
  const rows=$('#docRows');
  if(!filtered.length){ rows.innerHTML=`<tr><td colspan="5" class="table-empty">${docs.length?'سندی با این نام پیدا نشد.':'کتابخانه خالی است؛ اولین سند را بارگذاری کنید.'}</td></tr>`; }
  else rows.innerHTML=filtered.map(d=>{const mayDelete=currentUser?.role==='system_admin'||(currentUser?.role==='knowledge_manager'&&d.uploadedBy===currentUser.id);return `<tr><td><div class="doc-name-cell"><span class="file-icon">▤</span><span>${escapeHtml(d.name)}</span></div></td><td>${fmtSize(d.size)}</td><td>${fmtDate(d.addedAt)}</td><td><span class="status-ready">${d.municipalityScope?'محدود به واحد':'دسترسی سازمانی'}</span></td><td>${mayDelete?`<button class="delete-btn" title="حذف سند" aria-label="حذف ${escapeHtml(d.name)}" data-delete="${d.id}">×</button>`:'—'}</td></tr>`}).join('');
  rows.querySelectorAll('[data-delete]').forEach(b=>b.onclick=()=>deleteDoc(b.dataset.delete));
  const recent=$('#recentDocs');
  recent.innerHTML=docs.length ? docs.slice(0,4).map(d=>`<div class="recent-item"><span class="file-icon">▤</span><div><b>${escapeHtml(d.name)}</b><small>${fmtDate(d.addedAt)} · ${fmtSize(d.size)}</small></div><span>● آماده</span></div>`).join('') : `<div class="empty-inline"><span class="empty-icon">▤</span><b>هنوز سندی ندارید</b><span>اولین فایل را به کتابخانه اضافه کنید.</span><button class="btn btn-soft" data-go="documents">＋ افزودن سند</button></div>`;
  recent.querySelectorAll('[data-go]').forEach(b=>b.onclick=()=>navigate(b.dataset.go)); updateChatSources();
}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function loadData(){
  try { [docs,feedback]=await Promise.all([api('/api/documents'),api('/api/feedback')]); renderDocs(); renderFeedback(); }
  catch(e){toast(e.message)}
  try { const s=await api('/api/status'); $('#connectionText').textContent=s.ollama?'مدل هوش مصنوعی محلی متصل':'سرور محلی فعال'; $('#aiStatusTitle').textContent=s.ollama?'مدل هوش مصنوعی محلی آماده است':'جست‌وجوی محلی فعال است'; $('#aiStatusBody').textContent=s.ollama?`پاسخ‌ها با مدل ${s.model} و بر پایه اسناد داخلی ساخته می‌شوند.`:'با افزودن سند، جست‌وجوی محلی آماده است. برای پاسخ‌سازی هوشمند، مدل Ollama را روی سرور نصب کنید.'; $('#aiStatusChip').textContent=s.ollama?'هوش مصنوعی محلی':'بدون وابستگی به وب'; }
  catch { $('#connectionText').textContent='در حال اجرا روی سرور'; }
  $('#statQuestions').textContent=digits(Number(localStorage.getItem(`hy_chat_count_${currentUser?.id||'guest'}`)||0));
}
function renderFeedback(){
  const all=feedback; const ups=all.filter(x=>x.rating==='up').length, corrections=all.filter(x=>x.correction).length;
  $('#statFeedback').textContent=digits(all.length); $('#learnTotal').textContent=digits(all.length); $('#learnUp').textContent=digits(ups); $('#learnCorrections').textContent=digits(corrections);
  $('#feedbackList').innerHTML=all.length?all.map(f=>`<div class="feedback-entry"><span class="feedback-mark">${f.correction?'✎':f.rating==='up'?'✓':'↗'}</span><div><b>${escapeHtml(f.question)}</b>${f.correction?`<p>${escapeHtml(f.correction)}</p>`:`<p>${f.rating==='up'?'این پاسخ مفید بود.':'پاسخ نیاز به بررسی دارد.'}</p>`}<small>${fmtDate(f.createdAt)}</small></div></div>`).join(''):`<div class="empty-inline"><span class="empty-icon">↗</span><b>هنوز بازخوردی ثبت نشده</b><span>پس از هر پاسخ می‌توانید مفید بودن یا اصلاح پاسخ را ثبت کنید.</span></div>`;
}
function updateChatSources(){
  $('#chatDocCount').textContent=digits(docs.length); const el=$('#chatSourcesList');
  if(!el)return; el.innerHTML=docs.length?docs.slice(0,5).map(d=>`<div class="source-mini"><b>${escapeHtml(d.name)}</b><span>${fmtSize(d.size)} · آماده جست‌وجو</span></div>`).join(''):`<div class="source-placeholder">با افزودن اسناد، منابع اینجا نمایش داده می‌شوند.</div>`;
}
async function uploadFiles(fileList){
  for(const file of [...fileList]){
    const ext=file.name.split('.').pop().toLowerCase();
    if(!['txt','md','csv','json','log','html'].includes(ext)){toast(`فرمت ${file.name} پشتیبانی نمی‌شود.`);continue;}
    if(file.size>12*1024*1024){toast(`حجم ${file.name} بیشتر از ۱۲ مگابایت است.`);continue;}
    try{const text=await file.text();if(!text.trim()){toast(`فایل ${file.name} خالی است.`);continue;}const scopeChoice=$('#documentScope')?.value;const municipalityScope=scopeChoice==='local'?currentUser?.municipality:scopeChoice==='custom'?$('#municipalityTarget').value.trim():null;if(scopeChoice==='custom'&&!municipalityScope){toast('نام شهرداری مقصد را وارد کنید.');continue;}await api('/api/documents',{method:'POST',body:JSON.stringify({name:file.name,text,municipalityScope})});toast(`${file.name} به کتابخانه اضافه شد.`);}
    catch(e){toast(e.message)}
  }
  await loadData();
}
async function deleteDoc(id){const d=docs.find(x=>x.id===id);if(!d||!confirm(`سند «${d.name}» حذف شود؟`))return;try{await api('/api/documents/'+encodeURIComponent(id),{method:'DELETE'});toast('سند حذف شد.');await loadData();}catch(e){toast(e.message)}}
function addMessage(role,text){
  const container=$('#chatContent');let welcome=container.querySelector('.chat-welcome');if(welcome)welcome.remove();
  const msg=document.createElement('div');msg.className='message '+role;const av=document.createElement('span');av.className='message-avatar';av.textContent=role==='user'?'م‌':'✳';const bubble=document.createElement('div');bubble.className='bubble';bubble.textContent=text;msg.append(av,bubble);container.appendChild(msg);container.scrollTop=container.scrollHeight;return {msg,bubble};
}
async function ask(question){
  if(state.busy)return; question=(question||$('#questionInput').value).trim();if(!question)return;
  $('#questionInput').value='';$('#questionInput').rows=1; state.busy=true;$('#sendBtn').disabled=true;
  addMessage('user',question);const pending=document.createElement('div');pending.className='typing';pending.textContent='در حال جست‌وجو در اسناد داخلی...';$('#chatContent').append(pending);$('#chatContent').scrollTop=$('#chatContent').scrollHeight;
  try{
    const result=await api('/api/chat',{method:'POST',body:JSON.stringify({question})});pending.remove();const {msg,bubble}=addMessage('assistant',result.answer);
    if(result.sources?.length){const sourceBox=document.createElement('div');sourceBox.className='answer-sources';result.sources.forEach(s=>{const chip=document.createElement('div');chip.className='source-chip';const b=document.createElement('b');b.textContent='▤ '+s.name;const p=document.createElement('span');p.textContent=s.excerpt;chip.append(b,p);sourceBox.append(chip)});bubble.append(sourceBox);}
    const meta=document.createElement('div');meta.className='answer-meta';const mode=document.createElement('span');mode.textContent=result.mode==='local-ai'?'پاسخ با مدل محلی':'نتیجه جست‌وجوی محلی';const actions=document.createElement('span');actions.className='feedback-actions';const up=document.createElement('button');up.textContent='مفید بود';up.title='ثبت پاسخ مفید';up.onclick=()=>submitRating(question,'up',up);const down=document.createElement('button');down.textContent='نیاز به اصلاح';down.title='ثبت اصلاح پاسخ';down.onclick=()=>{pendingFeedback={question,answer:result.answer};$('#correctionText').value='';$('#correctionModal').classList.add('show')};actions.append(up,down);meta.append(mode,actions);bubble.append(meta);
    const count=Number(localStorage.getItem(`hy_chat_count_${currentUser?.id||'guest'}`)||0)+1;localStorage.setItem(`hy_chat_count_${currentUser?.id||'guest'}`,count);$('#statQuestions').textContent=digits(count);
    const list=$('#chatSourcesList');if(result.sources?.length){list.innerHTML=result.sources.slice(0,4).map(s=>`<div class="source-mini"><b>${escapeHtml(s.name)}</b><span>${escapeHtml(s.excerpt.slice(0,105))}…</span></div>`).join('');}
  }catch(e){pending.remove();addMessage('assistant',e.message)}finally{state.busy=false;$('#sendBtn').disabled=false;$('#chatContent').scrollTop=$('#chatContent').scrollHeight;}
}
async function submitRating(question,rating,button){
  try{await api('/api/feedback',{method:'POST',body:JSON.stringify({question,rating})});button.textContent='ثبت شد ✓';button.disabled=true;toast('بازخورد شما ثبت شد.');await loadData();}catch(e){toast(e.message)}
}
async function saveCorrection(){if(!pendingFeedback)return;const correction=$('#correctionText').value.trim();if(!correction){toast('متن اصلاحی را وارد کنید.');return;}try{await api('/api/feedback',{method:'POST',body:JSON.stringify({question:pendingFeedback.question,correction,rating:'down'})});$('#correctionModal').classList.remove('show');addMessage('assistant','سپاس از اصلاح شما. این بازخورد روی همین سرور ثبت شد و به‌عنوان راهنمای پاسخ‌های مشابه استفاده می‌شود.');pendingFeedback=null;toast('اصلاح شما ثبت شد.');await loadData();}catch(e){toast(e.message)}}

function resetChat(){$('#chatContent').innerHTML=`<div class="chat-welcome"><div class="welcome-orb"><span>✳</span></div><h2>چه چیزی می‌خواهید بدانید؟</h2><p>پاسخ‌ها از متن اسناد داخلی شما جست‌وجو می‌شوند و همراه منبع نمایش داده خواهند شد.</p><div class="chat-suggestions"><button data-question="شرایط و مراحل دریافت تسهیلات چیست؟">شرایط دریافت تسهیلات <span>↖</span></button><button data-question="آخرین مهلت ارسال گزارش‌ها چه زمانی است؟">مهلت ارسال گزارش‌ها <span>↖</span></button><button data-question="چه مدارکی برای درخواست لازم است؟">مدارک موردنیاز <span>↖</span></button></div></div>`;$$('#chatContent [data-question]').forEach(b=>b.onclick=()=>ask(b.dataset.question));$('#chatSourcesList').innerHTML='<div class="source-placeholder">با افزودن اسناد، منابع اینجا نمایش داده می‌شوند.</div>';$('#chatDocCount').textContent='۰';}
function forceLock(message){resetChat();try{sessionStorage.removeItem('hy_preview_token')}catch{}document.body.classList.remove('authenticated');currentUser=null;csrfToken=null;docs=[];feedback=[];$('#authPending').hidden=true;$('#phoneForm').hidden=false;$('#authTabs').hidden=false;$('#googleSignIn').hidden=false;$('.auth-divider').hidden=false;$('#otpFields').hidden=true;$('#devCode').hidden=true;$('#phoneInput').readOnly=false;$('#otpInput').value='';googlePhoneFlow=false;authChallenge=null;setAuthMode('login');setAuthStep('phone');if(message)authError(message);}
function authError(message){const el=$('#authError');el.textContent=message;el.hidden=!message;}
function setAuthMode(mode){authMode=mode;$$('[data-auth-tab]').forEach(b=>b.classList.toggle('selected',b.dataset.authTab===mode));$('#identityFields').hidden=mode!=='signup';$('#authTitle').textContent=mode==='signup'?'ساخت حساب سازمانی':'ورود به حساب کاربری';$('#authIntro').textContent=mode==='signup'?'مشخصات سازمانی خود را وارد کنید تا درخواست دسترسی ثبت شود.':'برای دسترسی به اسناد و پاسخ‌های سازمانی، هویت خود را تأیید کنید.';$('#authSubmit span').textContent='ارسال کد تأیید';authError('');}
function setAuthStep(step){authStep=step;const otp=step==='otp';const google=googlePhoneFlow;$('#otpFields').hidden=!otp;$('#authTabs').hidden=otp||google;$('#googleSignIn').hidden=otp||google;$('#googleNote').hidden=otp||google||!$('#googleSignIn').disabled;$('.auth-divider').hidden=otp||google;$('#identityFields').hidden=(!google&&authMode!=='signup');$('#authTitle').textContent=google?'اتصال شمارهٔ همراه':otp?'تأیید شمارهٔ همراه':authMode==='signup'?'ساخت حساب سازمانی':'ورود به حساب کاربری';$('#authIntro').textContent=google?'برای تکمیل ورود گوگل، شمارهٔ همراه سازمانی خود را تأیید کنید.':otp?'کد شش‌رقمی ارسال‌شده را وارد کنید تا ورود امن تکمیل شود.':authMode==='signup'?'مشخصات سازمانی خود را وارد کنید تا درخواست دسترسی ثبت شود.':'برای دسترسی به اسناد و پاسخ‌های سازمانی، هویت خود را تأیید کنید.';$('#authSubmit span').textContent=otp?'تأیید و ورود':'ارسال کد تأیید';$('#phoneInput').readOnly=otp;$('#phoneInput').classList.toggle('read-only',otp);$('#otpInput').value='';authError('');}
function showPending(user){document.body.classList.remove('authenticated');$('#phoneForm').hidden=true;$('#authTabs').hidden=true;$('#googleSignIn').hidden=true;$('.auth-divider').hidden=true;$('#authPending').hidden=false;$('#devCode').hidden=true;$('#authCard').querySelector('.auth-card-mark').textContent=user.status==='disabled'?'!':'◷';$('#pendingTitle').textContent=user.status==='disabled'?'حساب غیرفعال است':'درخواست دسترسی در انتظار تأیید';$('#pendingMessage').textContent=user.status==='disabled'?'برای فعال‌سازی حساب با مدیر سامانه تماس بگیرید.':`حساب ${user.municipality||'سازمانی'} ایجاد شد. پس از تأیید مدیر سامانه امکان ورود خواهید داشت.`;currentUser=user;}
async function enterApp(session){currentUser=session.user;csrfToken=session.csrfToken;try{if(session.previewToken)sessionStorage.setItem('hy_preview_token',session.previewToken);else sessionStorage.removeItem('hy_preview_token')}catch{}if(currentUser.status!=='active'){showPending(currentUser);return;}$('#authPending').hidden=true;$('#phoneForm').hidden=false;document.body.classList.add('authenticated');const roleNames={system_admin:'مدیر سامانه',knowledge_manager:'مدیر دانش',municipality_member:'کاربر شهرداری'};$('#profileName').textContent=currentUser.name;$('#greetingName').textContent=(currentUser.name||'خوش آمدید').trim().split(/\s+/)[0];$('#profileRole').textContent=`${roleNames[currentUser.role]||'کاربر'} · ${currentUser.municipality||'سازمان'}`;$('#profileAvatar').textContent=(currentUser.name||'ک').slice(0,1);$('#headerAvatar').textContent=(currentUser.name||'ک').slice(0,1);$('#usersNav').hidden=currentUser.role!=='system_admin';const canManageLibrary=['system_admin','knowledge_manager'].includes(currentUser.role);$('#scopeRow').hidden=!canManageLibrary;$('#uploadManagerPanel').hidden=!canManageLibrary;$('#documentReadOnly').hidden=canManageLibrary;$('#documentScope option[value="global"]').hidden=currentUser.role!=='system_admin';$('#documentScope option[value="custom"]').hidden=currentUser.role!=='system_admin';$('#documentScope').value=currentUser.role==='system_admin'?'global':'local';$('#municipalityTarget').hidden=true;$('#uploadTop').hidden=!['system_admin','knowledge_manager'].includes(currentUser.role);$('#browseBtn').disabled=!['system_admin','knowledge_manager'].includes(currentUser.role);$('#browseBtn').title='فقط مدیران دانش مجاز به بارگذاری هستند';if(location.search)history.replaceState(null,'',location.pathname+location.hash);const page=location.hash.slice(1)||'dashboard';navigate(page);await loadData();}
async function initializeAuth(){
  const params=new URLSearchParams(location.search);const configResult=await fetch('/api/auth/config').then(r=>r.json()).catch(()=>({}));
  $('.secure-label').lastChild.textContent=configResult.production?' اتصال HTTPS سازمانی':' محیط توسعه / پیش‌نمایش';$('#googleNote').hidden=configResult.googleEnabled&&configResult.phoneEnabled;$('#googleSignIn').disabled=!(configResult.googleEnabled&&configResult.phoneEnabled);$('#googleSignIn').title=configResult.googleEnabled&&configResult.phoneEnabled?'ورود امن با حساب گوگل':'برای فعال‌سازی ورود گوگل، OAuth و درگاه پیامک سرور باید تنظیم شوند';if(!configResult.phoneEnabled){$('#authSubmit').disabled=true;$('#authSubmit span').textContent='درگاه پیامک پیکربندی نشده';}
  $('#previewWarning').hidden=!configResult.devMode;$('#smsNote').hidden=configResult.phoneEnabled;
  if(params.get('google')==='verify-phone'){googlePhoneFlow=true;setAuthStep('phone');}
  try{const session=await api('/api/auth/me');if(session.authenticated){await enterApp(session);return;}if(session.config){$('#googleNote').hidden=session.config.googleEnabled&&session.config.phoneEnabled;$('#googleSignIn').disabled=!(session.config.googleEnabled&&session.config.phoneEnabled);$('#smsNote').hidden=session.config.phoneEnabled;if(!session.config.phoneEnabled){$('#authSubmit').disabled=true;$('#authSubmit span').textContent='درگاه پیامک پیکربندی نشده';}}}catch{}
  document.body.classList.remove('authenticated');if(!googlePhoneFlow)setAuthMode('login');if(params.get('authError'))authError('ورود گوگل تکمیل نشد؛ دوباره تلاش کنید.');
}
async function completeAuth(){
  const phone=$('#phoneInput').value.trim(), name=$('#fullName').value.trim(), municipality=$('#municipality').value.trim();
  if(authStep==='phone'){
    if(authMode==='signup'&&(!name||!municipality)){authError('نام کامل و شهرداری/واحد سازمانی را وارد کنید.');return;}
    const path=googlePhoneFlow?'/api/auth/google/complete-otp':'/api/auth/otp/request';$('#authSubmit').disabled=true;$('#authSubmit span').textContent='در حال ارسال کد...';authError('');
    try{const result=await api(path,{method:'POST',body:JSON.stringify({phone})});authChallenge={id:result.challengeId,phone};setAuthStep('otp');if(result.debugCode){$('#devCode').hidden=false;$('#devCode').textContent=`کد آزمایشی پیش‌نمایش: ${result.debugCode}`;}$('#otpInput').focus();}
    catch(e){authError(e.message)}finally{$('#authSubmit').disabled=false;$('#authSubmit span').textContent='ارسال کد تأیید';}
    return;
  }
  if(!authChallenge){authError('درخواست کد تأیید پیدا نشد؛ دوباره کد بگیرید.');setAuthStep('phone');return;}
  const code=$('#otpInput').value.trim().replace(/[۰-۹]/g,d=>String('۰۱۲۳۴۵۶۷۸۹'.indexOf(d))).replace(/[٠-٩]/g,d=>String('٠١٢٣٤٥٦٧٨٩'.indexOf(d)));if(!/^\d{6}$/.test(code)){authError('کد شش‌رقمی را وارد کنید.');return;}
  $('#authSubmit').disabled=true;$('#authSubmit span').textContent='در حال تأیید...';
  try{const result=await api('/api/auth/otp/verify',{method:'POST',body:JSON.stringify({challengeId:authChallenge.id,phone:authChallenge.phone,code,name,municipality})});authChallenge=null;googlePhoneFlow=false;await enterApp(result);}
  catch(e){if(e.message.includes('نام و نام خانوادگی')){authChallenge=null;setAuthMode('signup');setAuthStep('phone');$('#phoneInput').value=phone;authError('این شماره هنوز حساب ندارد. فرم ساخت حساب را تکمیل و کد تازه دریافت کنید.');}else authError(e.message)}finally{$('#authSubmit').disabled=false;if(authStep==='otp')$('#authSubmit span').textContent='تأیید و ورود';}
}
async function resendOtp(){if(!authChallenge)return;$('#resendOtp').disabled=true;try{const path=googlePhoneFlow?'/api/auth/google/complete-otp':'/api/auth/otp/request';const result=await api(path,{method:'POST',body:JSON.stringify({phone:authChallenge.phone})});authChallenge.id=result.challengeId;$('#otpInput').value='';authError('کد تازه ارسال شد.');if(result.debugCode){$('#devCode').hidden=false;$('#devCode').textContent=`کد آزمایشی پیش‌نمایش: ${result.debugCode}`;}}catch(e){authError(e.message)}finally{setTimeout(()=>$('#resendOtp').disabled=false,1200)}}
async function logout(){resetChat();try{await api('/api/auth/logout',{method:'POST',body:'{}'});}catch{}try{sessionStorage.removeItem('hy_preview_token')}catch{}csrfToken=null;currentUser=null;docs=[];feedback=[];document.body.classList.remove('authenticated');$('#authPending').hidden=true;$('#phoneForm').hidden=false;googlePhoneFlow=false;authChallenge=null;$('#phoneInput').value='';$('#phoneInput').readOnly=false;$('#otpInput').value='';$('#devCode').hidden=true;setAuthMode('login');setAuthStep('phone');toast('با موفقیت خارج شدید.');}
function roleLabel(role){return ({system_admin:'مدیر سامانه',knowledge_manager:'مدیر دانش',municipality_member:'کاربر شهرداری'})[role]||role;}
async function loadUsers(){if(currentUser?.role!=='system_admin')return;const rows=$('#userRows');try{const users=await api('/api/admin/users');$('#usersCount').textContent=`${digits(users.length)} کاربر`;rows.innerHTML=users.length?users.map(u=>`<tr><td><div class="admin-user"><span class="avatar">${escapeHtml((u.name||'ک').slice(0,1))}</span><div><b>${escapeHtml(u.name)}</b><small>${escapeHtml(u.phone)}${u.email?' · '+escapeHtml(u.email):''}</small></div></div></td><td><input class="admin-municipality" data-user-municipality="${u.id}" value="${escapeHtml(u.municipality||'')}" maxlength="100" aria-label="شهرداری ${escapeHtml(u.name)}"></td><td><select class="admin-select" data-user-role="${u.id}" ${u.id===currentUser.id?'disabled':''}><option value="municipality_member" ${u.role==='municipality_member'?'selected':''}>کاربر شهرداری</option><option value="knowledge_manager" ${u.role==='knowledge_manager'?'selected':''}>مدیر دانش</option><option value="system_admin" ${u.role==='system_admin'?'selected':''}>مدیر سامانه</option></select></td><td><select class="admin-select status-select" data-user-status="${u.id}"><option value="pending" ${u.status==='pending'?'selected':''}>در انتظار</option><option value="active" ${u.status==='active'?'selected':''}>فعال</option><option value="disabled" ${u.status==='disabled'?'selected':''}>غیرفعال</option></select></td><td><button class="save-access" data-save-user="${u.id}">ذخیره دسترسی</button></td></tr>`).join(''):`<tr><td colspan="5" class="table-empty">کاربری ثبت نشده است.</td></tr>`;
  rows.querySelectorAll('[data-save-user]').forEach(b=>b.onclick=()=>saveUserAccess(b.dataset.saveUser));}catch(e){rows.innerHTML=`<tr><td colspan="5" class="table-empty">${escapeHtml(e.message)}</td></tr>`;}}
async function saveUserAccess(id){const role=$(`[data-user-role="${CSS.escape(id)}"]`).value,status=$(`[data-user-status="${CSS.escape(id)}"]`).value,municipality=$(`[data-user-municipality="${CSS.escape(id)}"]`).value.trim();try{await api('/api/admin/users/'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify({role,status,municipality})});toast('دسترسی کاربر به‌روزرسانی شد.');await loadUsers();}catch(e){toast(e.message)}}

$('#phoneForm').addEventListener('submit',e=>{e.preventDefault();completeAuth()});
$$('[data-auth-tab]').forEach(b=>b.addEventListener('click',()=>setAuthMode(b.dataset.authTab)));
$('#googleSignIn').onclick=()=>{if(!$('#googleSignIn').disabled)location.href='/auth/google'};
$('#pendingLogout').onclick=logout;$('#logoutBtn').onclick=logout;$('#refreshUsers').onclick=loadUsers;$('#resendOtp').onclick=resendOtp;
$$('[data-page]').forEach(a=>a.addEventListener('click',e=>{e.preventDefault();navigate(a.dataset.page)}));
$$('[data-go]').forEach(b=>b.addEventListener('click',()=>navigate(b.dataset.go)));
window.addEventListener('hashchange',()=>navigate(location.hash.slice(1)));
$('#mobileMenu').onclick=()=>$('#sidebar').classList.toggle('open');
$('#documentScope').onchange=()=>{$('#municipalityTarget').hidden=$('#documentScope').value!=='custom'};$('#uploadTop').onclick=()=>$('#fileInput').click();$('#browseBtn').onclick=()=>$('#fileInput').click();$('#fileInput').onchange=e=>{uploadFiles(e.target.files);e.target.value=''};
const zone=$('#dropZone');['dragenter','dragover'].forEach(ev=>zone.addEventListener(ev,e=>{e.preventDefault();zone.classList.add('dragover')}));['dragleave','drop'].forEach(ev=>zone.addEventListener(ev,e=>{e.preventDefault();zone.classList.remove('dragover')}));zone.addEventListener('drop',e=>uploadFiles(e.dataTransfer.files));
$('#docSearch').oninput=renderDocs;$('#sendBtn').onclick=()=>ask();$('#questionInput').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();ask()}});$('#questionInput').addEventListener('input',e=>{e.target.rows=Math.min(5,Math.max(1,e.target.value.split('\n').length))});
$$('[data-question]').forEach(b=>b.addEventListener('click',()=>{navigate('chat');ask(b.dataset.question)}));
$('#newChat').onclick=resetChat;
$('#modalClose').onclick=()=>$('#correctionModal').classList.remove('show');$('#correctionModal').addEventListener('click',e=>{if(e.target.id==='correctionModal')e.currentTarget.classList.remove('show')});$('#saveCorrection').onclick=saveCorrection;
$('#helpBtn').onclick=()=>toast('اسناد متنی را بارگذاری کنید، سپس در گفت‌وگو پرسش بپرسید. برای پاسخ‌سازی زبانی، Ollama روی سرور نصب شود.');
initializeAuth();
