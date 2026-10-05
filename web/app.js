'use strict';
const $=id=>document.getElementById(id);
const money=n=>new Intl.NumberFormat('en-US',{style:'currency',currency:'USD'}).format(n/100);
function node(tag,text,cls){const n=document.createElement(tag);n.textContent=text;if(cls)n.className=cls;return n}
const labels={'00':'Approved','55':'Incorrect PIN','82':'Cryptogram rejected','51':'Insufficient funds'};
function render(r){
  $('scenario').value=r.scenario;
  $('response').textContent=r.responseCode+' · '+labels[r.responseCode];$('latency').textContent=r.latencyMs.toFixed(1)+' ms';$('balanced').textContent=r.balanced?'Yes':'No';
  const steps=[['ISO 8583 request',`${r.requestMti} → ${r.responseMti} · ${money(r.amountMinor)}`,true],['Issuer response',`${r.responseCode} · ${labels[r.responseCode]}`,r.passed],['Card verifies issuer',r.arpcVerified?'ARPC verified by the EMV card':r.responseCode==='82'?'Tampered ARQC rejected; no ARPC issued':'No successful authorization',r.responseCode==='00'?r.arpcVerified:true]];
  if(r.replayCode)steps.push(['Duplicate transmission','Same request returns code '+r.replayCode,true]);
  if(r.reversalCode)steps.push(['Release hold','0400 reversal returns '+r.reversalCode+'; held amount returns to zero',r.finalAccount.heldMinor===0]);
  steps.push(['Double-entry ledger','Postings balance and stored balances match',r.balanced&&r.balancesMatch]);
  $('steps').replaceChildren(...steps.map(([title,detail,ok])=>{const row=node('div','','step'),body=node('div','');body.append(node('strong',title),node('p',detail));row.append(node('span',ok?'✓':'!','pass'),body);return row}));
  const head=node('tr','');['Stage','Held','Available'].forEach(s=>head.append(node('th',s)));$('head').replaceChildren(head);
  $('rows').replaceChildren(...[['After authorization',r.heldAccount],['After cleanup',r.finalAccount]].map(([label,a])=>{const row=node('tr','');row.append(node('td',label),node('td',money(a.heldMinor),'num'),node('td',money(a.availableMinor),'num'));return row}));
  $('timestamp').textContent='Verified '+new Date(r.at).toLocaleString();$('raw').textContent=JSON.stringify(r,null,2);
}
async function status(){try{const r=await(await fetch('api/status')).json();$('status').textContent=r.online?'Live · Switch, HSM, and issuer online':'Services starting…';$('status').classList.toggle('live',r.online);if(r.last)render(r.last);else $('steps').replaceChildren(node('p','Choose a scenario to inspect the live authorization.'));}catch{$('status').textContent='Unable to reach services. Refresh to try again.'}}
$('run').addEventListener('click',async()=>{const b=$('run');b.disabled=true;b.textContent='Authorizing…';$('error').classList.add('hidden');try{const res=await fetch('api/run?scenario='+encodeURIComponent($('scenario').value),{method:'POST'}),r=await res.json();if(!res.ok)throw Error(r.error);render(r);}catch(e){$('error').textContent=e.message;$('error').classList.remove('hidden');}finally{b.disabled=false;b.textContent='Send authorization';}});status();
