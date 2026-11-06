const API = {
  base: '',
  get token(){ return localStorage.getItem('saas_token') || ''; },
  set token(v){ if(v) localStorage.setItem('saas_token', v); else localStorage.removeItem('saas_token'); },
  get role(){ return localStorage.getItem('saas_role') || ''; },
  set role(v){ if(v) localStorage.setItem('saas_role', v); else localStorage.removeItem('saas_role'); },
  async req(path, opts={}){
    const headers = Object.assign({'Content-Type':'application/json'}, opts.headers||{});
    if(this.token) headers.Authorization = 'Bearer ' + this.token;
    const r = await fetch(this.base + path, Object.assign({}, opts, {headers}));
    const data = await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(data.error || ('Error ' + r.status));
    return data;
  }
};
function show(el, msg){ if(!el) return; el.style.display='block'; el.textContent=msg; }
function hide(el){ if(el) el.style.display='none'; }
