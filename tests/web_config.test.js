'use strict';
// Pure VM/DOM-stub regression for actual bundled UI logic, not a visual/browser test.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.dataset = {}; this.textContent = ''; this.value = ''; this.classList = {toggle(){}}; }
  addEventListener(event,handler) { (this.events ||= {})[event]=handler; }
  append(...children) { for (const child of children) { child.parentNode = this; this.children.push(child); } }
  replaceChildren(...children) { this.children = []; this.append(...children); }
  contains(element) {return walk(this).includes(element);}
  setAttribute(){}
  querySelectorAll(selector) {return walk(this).filter(e=>selector==='input,select' && ['input','select'].includes(e.tagName));}
  checkValidity() {return true;}
  reportValidity() {return true;}
}
const pair = prefix => [{key:'secret_id_env',label:'ID',required:true,env_prefix:prefix},{key:'secret_key_env',label:'Key',required:true,env_prefix:prefix}];
const token = prefix => [{key:'token_env',label:'Token',required:true,env_prefix:prefix}];
const registry = [
  {kind:'namecheap',label:'Namecheap',implemented:true,supports_dns_read:true,credential_fields:pair('NAMECHEAP_'),options:['scope','write_mode','environment','sld','tld','client_ip_env'].map(key=>({key,label:key,required:true})),record_options:[]},
  {kind:'trafficroute',label:'Volcengine TrafficRoute',implemented:true,supports_dns_read:true,credential_fields:pair('TRAFFICROUTE_'),options:['scope','api_version','region','zone_id'].map(key=>({key,label:key,required:true})),record_options:[]},
  {kind:'callback',label:'Independent callback',implemented:true,supports_dns_read:false,credential_fields:token('CALLBACK_'),options:['endpoint_env','mode','verification','delivery','ttl_mode'].map(key=>({key,label:key,required:true})),record_options:[]},
  {kind:'huaweicloud',label:'Huawei Cloud DNS',implemented:true,credential_fields:pair('HUAWEICLOUD_'),options:[{key:'region',label:'Region',required:true},{key:'project_id',label:'Project ID',required:true},{key:'zone_id',label:'Zone ID',required:false}],record_options:[{key:'zone_id',label:'Zone ID',required:false}]},
  {kind:'baiducloud',label:'Baidu Cloud DNS',implemented:true,credential_fields:pair('BAIDUCLOUD_'),options:[{key:'resource_id',label:'Resource ID',required:true}],record_options:[]},
  {kind:'edgeone',label:'Tencent EdgeOne',implemented:true,credential_fields:pair('EDGEONE_'),options:['mode','scope','api_version','zone_id'].map(key=>({key,label:key,required:true})),record_options:[]},
  {kind:'namesilo',label:'NameSilo',implemented:true,credential_fields:token('NAMESILO_'),options:[],record_options:[]},
  {kind:'hipmdnsmgr',label:'HiPM DNS Manager',implemented:true,credential_fields:token('HIPM_'),options:[{key:'endpoint_env',label:'Endpoint env',required:true},{key:'domain_id',label:'Domain ID',required:false}],record_options:[]},
  {kind:'dynv6',label:'dynv6',implemented:true,credential_fields:token('DYNV6_'),options:[{key:'ttl_mode',label:'TTL mode',required:true}],record_options:[]},
  {kind:'spaceship',label:'Spaceship',implemented:true,credential_fields:pair('SPACESHIP_'),options:[],record_options:[]},
  {kind:'gcore',label:'Gcore',implemented:true,credential_fields:token('GCORE_'),options:[{key:'plan',label:'Plan',required:false}],record_options:[]},
];
function harness(locale = 'zh', fetchImpl = null) {
  const elements = new Map();
  const document = {documentElement:{},getElementById(id){ if (!elements.has(id)) elements.set(id,new Element()); return elements.get(id); },createElement(tag){return new Element(tag);},querySelectorAll(selector){if(selector==='[data-direct-credential]')return [...elements.values()].flatMap(walk).filter(e=>e.dataset.directCredential);return [];}};
  const storage = {getItem(key){return key === 'ddns.locale' ? locale : null;},setItem(){},removeItem(){}};
  const context = {document,window:{localStorage:storage,sessionStorage:storage,addEventListener(){},confirm(){return true;}},console,TextEncoder,TypeError,AbortController,URLSearchParams,setTimeout,clearTimeout,setInterval(){return 1;},clearInterval(){},fetch:fetchImpl || (()=>{throw new Error('Unexpected fetch');})};
  const source = fs.readFileSync(path.join(__dirname,'../web/app.js'),'utf8');
  const startup = "$('token').value=state.token;translate();checkAuth();";
  assert.ok(source.includes(startup));
  vm.runInNewContext(source.replace(startup,'globalThis.uiTest={state,validateRegistry,validateConfig,renderConfig,renderStatus,switchProviderKind,validateAccount,maskedConfig,configPayload,acceptConfig,acceptSettings,renderAuth,checkAuth,connect,logout,disconnect,api,wipePasswords};'),context);
  context.uiTest.state.registry = context.uiTest.validateRegistry(JSON.parse(JSON.stringify(registry)));
  for(const id of ['username','password','confirmPassword'])document.getElementById(id);
  return {...context.uiTest,elements};
}
function config(kind = 'dynv6') {
  const provider = {name:'account',kind,secret_id_env:'',secret_key_env:'',token_env:'',options:{}};
  if (kind === 'namecheap') {provider.secret_id_env='NAMECHEAP_ACCOUNT_USER';provider.secret_key_env='NAMECHEAP_ACCOUNT_KEY';provider.options={scope:'basicdns_plain',write_mode:'exclusive_full_zone',environment:'production',sld:'example',tld:'com',client_ip_env:'NAMECHEAP_ACCOUNT_SERVER_IP'};}
  if (kind === 'trafficroute') {provider.secret_id_env='TRAFFICROUTE_AK';provider.secret_key_env='TRAFFICROUTE_SK';provider.options={scope:'public_dns',api_version:'2018-08-01',region:'cn-beijing',zone_id:'123'};}
  if (kind === 'callback') {provider.token_env='CALLBACK_ACCOUNT_TOKEN';provider.options={endpoint_env:'CALLBACK_ACCOUNT_ENDPOINT',mode:'json_post',verification:'unverified',delivery:'every_run',ttl_mode:'metadata_only'};}
  if (kind === 'namesilo') provider.token_env='NAMESILO_KEY';
  if (kind === 'hipmdnsmgr') {provider.token_env='HIPM_TOKEN';provider.options.endpoint_env='HIPM_ORIGIN';}
  if (kind === 'dynv6') {provider.token_env='DYNV6_TOKEN';provider.options.ttl_mode='provider_default';}
  if (kind === 'spaceship') {provider.secret_id_env='SPACESHIP_API_KEY';provider.secret_key_env='SPACESHIP_API_SECRET';}
  if (kind === 'gcore') {provider.token_env='GCORE_API_KEY';provider.options.plan='free';}
  if (['huaweicloud','baiducloud','edgeone'].includes(kind)) {
    const prefix={huaweicloud:'HUAWEICLOUD_',baiducloud:'BAIDUCLOUD_',edgeone:'EDGEONE_'}[kind];provider.secret_id_env=prefix+'ID';provider.secret_key_env=prefix+'KEY';
    provider.options=kind==='huaweicloud'?{region:'cn-north-4',project_id:'project-native',zone_id:'zone-native'}:kind==='baiducloud'?{resource_id:'resource-native'}:{mode:'dns',scope:'teodns',api_version:'2022-09-01',zone_id:'zone-native'};
  }
  return {interval_secs:300,timeout_secs:15,log_level:'info',providers:[provider],records:[{name:'home',provider:'account',domain:'example.com',subdomain:'home',record_type:'A',record_line:kind==='hipmdnsmgr'?'default':'默认',ttl:600,record_id:null,options:{},create_if_missing:false,enabled:false,ip_source:{kind:'static',value:'1.1.1.1'}}]};
}
function walk(element) {return [element,...element.children.flatMap(walk)];}
function text(element) {return walk(element).map(e=>e.textContent).join(' ');}

test('interface source hides addressless adapters and previews matching addresses or a regex error',async()=>{
  const q=fetchQueue(response(['240e::2','240e::10']),response({error:'Invalid IP regex'},422),response([]));
  const h=harness('en',q.fetch),c=config();
  h.state.config=c;
  h.state.interfaces=[
    {name:'Wi-Fi',ipv4:['1.1.1.1','1.1.1.2'],ipv6:['240e::2','240e::10']},
    {name:'Ethernet',ipv4:[],ipv6:[]},
    {name:'IPv6 only',ipv4:[],ipv6:['240e::20']}
  ];
  h.renderConfig();
  const records=h.elements.get('records');
  const select=option=>walk(records).find(e=>e.tagName==='select'&&e.children.some(o=>o.value===option));
  const sourceKind=select('interface');
  sourceKind.value='interface';sourceKind.events.change();
  const adapter=select('Wi-Fi');
  assert.ok(!adapter.children.some(o=>o.value==='Ethernet'));
  adapter.value='IPv6 only';adapter.events.change();
  assert.match(text(records),/no addresses for this family/);
  adapter.value='Wi-Fi';adapter.events.change();
  assert.match(text(records),/1\.1\.1\.1, 1\.1\.1\.2/);
  assert.doesNotMatch(text(records),/240e::/);
  const filter=walk(records).find(e=>e.tagName==='input'&&e.parentNode.children[0].textContent.includes('IP regex'));
  filter.value='^240e:';filter.events.input();
  const recordType=select('AAAA');
  recordType.value='AAAA';recordType.events.change();
  assert.match(text(records),/240e::2, 240e::10/);
  assert.doesNotMatch(text(records),/1\.1\.1\.1/);
  assert.match(text(records),/first in ascending numeric IP order/);
  h.validateConfig(h.configPayload(c));
  assert.equal(h.configPayload(c).records[0].ip_source.regex,'^240e:');
  const preview=()=>walk(records).find(e=>e.className==='field-help interface-preview');
  const waitForPreview=()=>new Promise(resolve=>setTimeout(resolve,250));
  await waitForPreview();
  assert.equal(q.calls[0].url,'/api/interfaces/preview');
  assert.deepEqual(JSON.parse(q.calls[0].options.body),{record_type:'AAAA',ip_source:{kind:'interface',value:'Wi-Fi',regex:'^240e:'}});
  assert.equal(preview().textContent,'Matches · 240e::2 (Selected for update), 240e::10');
  const activeFilter=walk(records).find(e=>e.tagName==='input'&&e.parentNode.children[0].textContent.includes('IP regex'));
  activeFilter.value='(';activeFilter.events.input();
  await waitForPreview();
  assert.equal(preview().textContent,'Invalid regular expression.');
  activeFilter.value='^2606:';activeFilter.events.input();
  await waitForPreview();
  assert.equal(preview().textContent,'No matching public addresses.');
  sourceKind.value='static';sourceKind.events.change();
  assert.equal(c.records[0].ip_source.regex,undefined);
});

test('dynv6 TTL opt-in is required and cannot claim fixed TTL',()=>{
  const h=harness();h.validateConfig(config());
  for (const options of [{},{ttl_mode:''},{ttl_mode:'fixed_60'}]) {const c=config();c.providers[0].options=options;assert.throws(()=>h.validateConfig(c));}
});
test('provider-managed TTL field is disabled with bilingual warning',()=>{
  for (const locale of ['zh','en']) {const h=harness(locale);h.state.config=config();h.renderConfig();const records=h.elements.get('records');assert.ok(walk(records).some(e=>e.tagName==='input'&&e.type==='number'&&e.value===600&&e.disabled));assert.match(text(records),locale==='zh'?/配置 TTL 不生效/:/Configured TTL is ignored/);}
});
test('Spaceship singleton and partial-update warning is visible; opaque IDs survive',()=>{
  const h=harness('en');const c=config('spaceship');const id='rrset-'+'a'.repeat(64);c.records[0].record_id=id;h.validateConfig(c);h.state.config=c;h.renderConfig();assert.equal(c.records[0].record_id,id);assert.match(text(h.elements.get('records')),/Non-atomic failures may leave both values/);assert.ok(!walk(h.elements.get('records')).some(e=>e.type==='number'&&e.disabled));
});
test('switching provider clears old credentials, IDs and incompatible options',()=>{
  const h=harness();h.state.config=config();h.state.config.records[0].record_id='123';h.switchProviderKind(h.state.config.providers[0],'spaceship');const p=h.state.config.providers[0];assert.equal(p.token_env,'');assert.equal(Object.keys(p.options).length,0);assert.equal(h.state.config.records[0].record_id,null);
});
test('Gcore actual-plan declaration rejects invalid values and discloses limits',()=>{
  const h=harness('en');const c=config('gcore');h.validateConfig(c);h.state.config=c;h.renderConfig();assert.match(text(h.elements.get('records')),/does not independently verify account entitlement/);c.providers[0].options.plan='premium';assert.throws(()=>h.validateConfig(c));
});
test('new credential namespaces reject secrets and arbitrary env references',()=>{
  const h=harness();for (const kind of ['dynv6','spaceship','gcore']) {const c=config(kind);const key=kind==='spaceship'?'secret_key_env':'token_env';c.providers[0][key]='PATH';assert.throws(()=>h.validateConfig(c));}
});

test('NameSilo token-only descriptor preserves stable logical ID and warns about GET key',()=>{
  for(const locale of ['zh','en']) {const h=harness(locale),c=config('namesilo');c.records[0].record_id='namesilo-'+'a'.repeat(64);h.validateConfig(c);h.state.config=c;h.renderConfig();assert.match(text(h.elements.get('records')),/GET/);assert.match(text(h.elements.get('records')),/namesilo-hash/);assert.equal(c.records[0].record_id,'namesilo-'+'a'.repeat(64));c.providers[0].options.endpoint_env='HIPM_ORIGIN';assert.throws(()=>h.validateConfig(c));}
});
test('HiPM endpoint is a scoped reference only; canonical int64 domain IDs',()=>{
  const h=harness();h.validateConfig(config('hipmdnsmgr'));
  for(const name of ['', 'PATH','DDNS_ORIGIN','OTHER_ORIGIN','HIPM_','HIPM_lower','http://127.0.0.1','https://private.example','HIPM_'+ 'A'.repeat(60)]){const c=config('hipmdnsmgr');c.providers[0].options.endpoint_env=name;assert.throws(()=>h.validateConfig(c));}
  for(const id of ['0','01','-1','+1','1.0','9223372036854775808','../1']){const c=config('hipmdnsmgr');c.providers[0].options.domain_id=id;assert.throws(()=>h.validateConfig(c));}
  const c=config('hipmdnsmgr');c.providers[0].options.domain_id='9223372036854775807';c.providers[0].token_env='DDNS_TEST_TOKEN';h.validateConfig(c);
  for(const options of [{endpoint_env:'HIPM_ORIGIN',endpoint:'https://private.example'},{endpoint_env:'HIPM_ORIGIN',insecure:'true'}]){c.providers[0].options=options;assert.throws(()=>h.validateConfig(c));}
});
test('HiPM native lines and IDs survive; switching does not guess display-label mapping',()=>{
  const h=harness('en'),c=config('hipmdnsmgr');c.records[0].record_id='native-123';h.validateConfig(c);h.state.config=c;h.renderConfig();assert.match(text(h.elements.get('records')),/actual native Aliyun ASCII/);assert.match(text(h.elements.get('providers')),/never reads or returns the actual URL/);assert.match(text(h.elements.get('providers')),/Manager domain ID/);
  for(const line of ['默认',' default','default ','def\tault']){const bad=config('hipmdnsmgr');bad.records[0].record_line=line;assert.throws(()=>h.validateConfig(bad));}
  h.state.config=config('namesilo');h.switchProviderKind(h.state.config.providers[0],'hipmdnsmgr');assert.equal(h.state.config.records[0].record_line,'默认');assert.equal(h.state.config.records[0].record_id,null);
});
test('HiPM duplicate line aliases and native record IDs are refused',()=>{
 const h=harness(),c=config('hipmdnsmgr');const r=JSON.parse(JSON.stringify(c.records[0]));r.name='other';r.record_line='DEFAULT';c.records.push(r);assert.throws(()=>h.validateConfig(c));r.record_line='telecom';h.validateConfig(c);c.records[0].record_id=r.record_id='native123';assert.throws(()=>h.validateConfig(c));
});
test('batch7 native IDs, dotted relative names and options survive actual form rendering',()=>{
 for(const kind of ['huaweicloud','baiducloud','edgeone']) {const h=harness('en'),c=config(kind);c.records[0].subdomain='home.nested';c.records[0].record_id={huaweicloud:'rrset-native',baiducloud:'2147483647',edgeone:'record-native'}[kind];h.validateConfig(c);h.state.config=c;h.renderConfig();assert.equal(c.records[0].subdomain,'home.nested');assert.equal(c.records[0].record_id,{huaweicloud:'rrset-native',baiducloud:'2147483647',edgeone:'record-native'}[kind]);for(const f of registry.find(d=>d.kind===kind).options.filter(f=>f.required)){const bad=config(kind);delete bad.providers[0].options[f.key];assert.throws(()=>h.validateConfig(bad));}}
});
test('Huawei required region/project, safe IDs, agreement and conservative TTL fail locally',()=>{
 const h=harness();for(const [key,values] of [['region',['cn-fake-1','cn-north-4.evil','https://evil']],['project_id',['.','..','0','../project']],['zone_id',['.','..','zone/other']]])for(const v of values){const c=config('huaweicloud');c.providers[0].options[key]=v;assert.throws(()=>h.validateConfig(c));}
 const c=config('huaweicloud');c.records[0].options.zone_id='zone-native';h.validateConfig(c);c.records[0].options.zone_id='zone-other';assert.throws(()=>h.validateConfig(c));delete c.providers[0].options.zone_id;h.validateConfig(c);
 for(const ttl of [1,299]){const c=config('huaweicloud');c.records[0].ttl=ttl;assert.throws(()=>h.validateConfig(c));}for(const line of ['DEFAULT','telecom']){const c=config('huaweicloud');c.records[0].record_line=line;assert.throws(()=>h.validateConfig(c));}
});
test('BCD native relative names, exact line aliases, int32 IDs and TTL limits',()=>{
 const h=harness();for(const line of ['DEFAULT','default','默认','CMNET','CNC','EDU','SEARCH']){const c=config('baiducloud');c.records[0].record_line=line;c.records[0].subdomain='home.nested';h.validateConfig(c);}
 for(const id of ['01','+1','0','2147483648','record-native']){const c=config('baiducloud');c.records[0].record_id=id;assert.throws(()=>h.validateConfig(c));}
 for(const line of ['Default','cmnet','telecom']){const c=config('baiducloud');c.records[0].record_line=line;assert.throws(()=>h.validateConfig(c));}
 for(const ttl of [59,3601]){const c=config('baiducloud');c.records[0].ttl=ttl;assert.throws(()=>h.validateConfig(c));}
 for(const resource_id of ['.','..','0','resource/other']){const c=config('baiducloud');c.providers[0].options.resource_id=resource_id;assert.throws(()=>h.validateConfig(c));}
});
test('EdgeOne explicit native TEODNS scope/version/IDs and TTL cannot become Origin',()=>{
 const h=harness();for(const [key,value] of [['mode','origin'],['scope','origin'],['api_version','latest'],['zone_id','origin-native']]){const c=config('edgeone');c.providers[0].options[key]=value;assert.throws(()=>h.validateConfig(c));}
 for(const id of ['origin-native','record/other']){const c=config('edgeone');c.records[0].record_id=id;assert.throws(()=>h.validateConfig(c));}for(const ttl of [59,86401]){const c=config('edgeone');c.records[0].ttl=ttl;assert.throws(()=>h.validateConfig(c));}
 for(const line of ['Default\n','CN.\u0000BJ']){const c=config('edgeone');c.records[0].record_line=line;assert.throws(()=>h.validateConfig(c));}
 for(const line of ['Default','default','默认','CN.BJ']){const c=config('edgeone');c.records[0].record_line=line;h.validateConfig(c);}
});
test('batch7 duplicate targets canonicalize only actual default aliases and preserve routing',()=>{
 const h=harness();for(const [kind,aliases,routed] of [['huaweicloud',['default','default_view','默认'],null],['baiducloud',['default','DEFAULT','默认'],'CMNET'],['edgeone',['default','Default','默认'],'CN.BJ']])for(const alias of aliases){const c=config(kind),other=JSON.parse(JSON.stringify(c.records[0]));other.name='second';other.record_line=alias;c.records.push(other);assert.throws(()=>h.validateConfig(c));if(routed){other.record_line=routed;h.validateConfig(c);c.records[0].record_id=other.record_id=kind==='baiducloud'?'123':'record-native';assert.throws(()=>h.validateConfig(c));}}
});
test('batch7 all credentials env-only and endpoint/group/region overrides rejected',()=>{
 const h=harness();for(const kind of ['huaweicloud','baiducloud','edgeone']){for(const value of ['PATH','OTHER_SECRET','literal-secret','DDNS_']){const c=config(kind);c.providers[0].secret_key_env=value;assert.throws(()=>h.validateConfig(c));}const c=config(kind);c.providers[0].secret_id_env='DDNS_TEST_ID';c.providers[0].secret_key_env='DDNS_TEST_KEY';h.validateConfig(c);for(const key of ['endpoint','group','region_override','min_ttl']){const bad=config(kind);bad.providers[0].options[key]='untrusted';assert.throws(()=>h.validateConfig(bad));}}
});
test('batch7 bilingual safety warnings and required labels match actual cloud contracts',()=>{
 for(const locale of ['zh','en'])for(const kind of ['huaweicloud','baiducloud','edgeone']){const h=harness(locale);h.state.config=config(kind);h.renderConfig();const providers=text(h.elements.get('providers')),records=text(h.elements.get('records'));for(const marker of {huaweicloud:['PUBLIC','ACTIVE','default_view','WritePending','project_id','300'],baiducloud:['resource_id','nameserver','CMNET','CNC','EDU','SEARCH','int32'],edgeone:['TEODNS','Origin','DescribeZones','DescribeDnsRecords','DescribeAccelerationDomains','DescribeApplicationProxies','2022-09-01']}[kind]){assert.ok(providers.toLowerCase().includes(marker.toLowerCase()),marker);assert.ok(records.toLowerCase().includes(marker.toLowerCase()),marker);}if(kind==='huaweicloud')assert.ok(!walk(h.elements.get('providers')).some(e=>e.placeholder==='cn-hangzhou'));if(kind==='edgeone')assert.match(providers,/zone-\.\.\./);}
});
test('switching new providers edits draft only and clears cross-provider IDs and credentials',()=>{
 const h=harness();h.state.config=config('huaweicloud');h.state.config.records[0].record_id='rrset-native';h.state.config.records[0].options.zone_id='zone-native';h.switchProviderKind(h.state.config.providers[0],'edgeone');assert.equal(h.state.config.records[0].record_id,null);assert.equal(Object.keys(h.state.config.records[0].options).length,0);assert.equal(h.state.config.providers[0].secret_id_env,'');assert.equal(h.state.config.providers[0].secret_key_env,'');assert.equal(h.state.config.records[0].enabled,false);assert.equal(h.state.config.records[0].create_if_missing,false);
});

 test('new HiPM records default to native code without rewriting existing records',()=>{
 const h=harness();h.state.config=config('hipmdnsmgr');h.state.config.records[0].record_line='telecom';h.elements.get('addRecord').events.click();assert.equal(h.state.config.records[0].record_line,'telecom');assert.equal(h.state.config.records[1].record_line,'default');
});

test('TrafficRoute actual scope signing region version and canonical int64 IDs validate locally',()=>{
 const h=harness();h.validateConfig(config('trafficroute'));
 for(const [key,value] of [['scope','gtm'],['api_version','latest'],['region','cn-north-1'],['zone_id','01'],['zone_id','9223372036854775808'],['endpoint','https://evil.invalid/']]){const c=config('trafficroute');c.providers[0].options[key]=value;assert.throws(()=>h.validateConfig(c));}
 for(const id of ['native-id','01','0','9223372036854775808','..']){const c=config('trafficroute');c.records[0].record_id=id;assert.throws(()=>h.validateConfig(c));}
 for(const ttl of [1,86400]){const c=config('trafficroute');c.records[0].ttl=ttl;h.validateConfig(c);}const c=config('trafficroute');c.records[0].ttl=86401;assert.throws(()=>h.validateConfig(c));
});
test('TrafficRoute duplicates use source-backed exact aliases not invented uppercase mapping',()=>{
 const h=harness();for(const alias of ['', 'default','默认']){const c=config('trafficroute'),r=JSON.parse(JSON.stringify(c.records[0]));r.name='second';r.record_line=alias;c.records.push(r);assert.throws(()=>h.validateConfig(c));r.record_line='DEFAULT';h.validateConfig(c);}
 for(const line of ['bad line','bad/line','..','default\n']){const c=config('trafficroute');c.records[0].record_line=line;assert.throws(()=>h.validateConfig(c));}
});
test('TrafficRoute bilingual Volcengine NS Stage0 pagination RRset and actual-account TTL help',()=>{
 for(const locale of ['zh','en']){const h=harness(locale);h.state.config=config('trafficroute');h.renderConfig();const all=text(h.elements.get('providers'))+' '+text(h.elements.get('records'));for(const marker of ['Volcengine','DNSPod','ListLines','RRset','GTMLockTags','2018-08-01','cn-beijing','dns.volcengineapi.com'])assert.ok(all.includes(marker),marker);}
});
test('Callback explicit acknowledgement and scoped endpoint names never accept URL or GET templates',()=>{
 const h=harness();h.validateConfig(config('callback'));for(const name of ['CALLBACK_','DDNS_URL','PATH','https://private.invalid/','CALLBACK_lower','CALLBACK_'+'A'.repeat(56)]){const c=config('callback');c.providers[0].options.endpoint_env=name;assert.throws(()=>h.validateConfig(c));}
 for(const [key,value] of [['mode','get'],['verification','verified'],['delivery','on_change'],['ttl_mode','provider_default'],['url','https://private.invalid/']]){const c=config('callback');c.providers[0].options[key]=value;assert.throws(()=>h.validateConfig(c));}
 const c=config('callback');c.providers[0].token_env='DDNS_OTHER_ACCOUNT';h.validateConfig(c);
});
test('Callback rejects record ID options and creation and line cannot bypass duplicate target',()=>{
 const h=harness();for(const [key,value] of [['record_id','123'],['options',{line:'telecom'}],['create_if_missing',true]]){const c=config('callback');c.records[0][key]=value;assert.throws(()=>h.validateConfig(c));}
 const c=config('callback'),r=JSON.parse(JSON.stringify(c.records[0]));r.name='second';r.record_line='telecom';c.records.push(r);assert.throws(()=>h.validateConfig(c));
});
test('Callback bilingual ignored DNS controls and no-DNS receiver protocol warnings visible',()=>{
 for(const locale of ['zh','en']){const h=harness(locale);h.state.config=config('callback');h.renderConfig();const records=h.elements.get('records');assert.ok(walk(records).some(e=>e.type==='checkbox'&&e.disabled&&!e.checked));assert.ok(walk(records).some(e=>e.tagName==='input'&&e.disabled&&e.value==='默认'));assert.ok(walk(records).some(e=>e.tagName==='input'&&e.disabled&&e.value===''));const all=text(records)+text(h.elements.get('providers'));for(const marker of ['UNVERIFIED','delivery_id','record_type','metadata','JSON POST'])assert.ok(all.toLowerCase().includes(marker.toLowerCase()),marker);}
});
test('Callback actual result labels remain amber UNVERIFIED in both locales not DNS updated',()=>{
 for(const locale of ['zh','en'])for(const status of ['callback_accepted_unverified','would_call_unverified']){const h=harness(locale);h.state.status={running:false,last_run:{run_id:'test',dry_run:status==='would_call_unverified',results:[{name:'callback',status,ip:'1.1.1.1',outcome:{status,previous_ip:null,record_id:null},error:null}]}};h.renderStatus();const results=h.elements.get('results');assert.match(text(results),/UNVERIFIED/);assert.ok(walk(results).some(e=>e.className==='badge warning'&&e.textContent.includes('UNVERIFIED')));assert.ok(!walk(results).some(e=>e.className==='badge safe'));}
});
test('Switching to callback clears IDs create and all previous scope options in draft only',()=>{
 const h=harness();h.state.config=config('trafficroute');h.state.config.records[0].record_id='123';h.state.config.records[0].create_if_missing=true;h.switchProviderKind(h.state.config.providers[0],'callback');assert.equal(h.state.config.records[0].record_id,null);assert.equal(h.state.config.records[0].create_if_missing,false);assert.equal(Object.keys(h.state.config.providers[0].options).length,0);assert.equal(h.state.config.providers[0].secret_id_env,'');assert.equal(h.state.config.records[0].enabled,false);
});

test('Namecheap account pair and explicit whole-zone acknowledgement survive without actual IP or native HostId',()=>{
 const h=harness(),c=config('namecheap');c.records[0].record_id='namecheap-'+'a'.repeat(64);h.validateConfig(c);h.state.config=c;h.renderConfig();assert.equal(c.records[0].record_id,'namecheap-'+'a'.repeat(64));assert.equal(c.providers[0].options.client_ip_env,'NAMECHEAP_ACCOUNT_SERVER_IP');assert.ok(!JSON.stringify(c.providers[0]).includes('1.1.1.1'));
 for(const key of registry[0].options.map(f=>f.key)){const bad=config('namecheap');delete bad.providers[0].options[key];assert.throws(()=>h.validateConfig(bad));}
 for(const ref of ['NAMECHEAP_OTHER_TOKEN','DDNS_ACCOUNT_TOKEN']){const good=config('namecheap');good.providers[0].secret_id_env=ref;good.providers[0].secret_key_env=ref+'_KEY';h.validateConfig(good);}
 for(const key of ['token_env','secret_id_env','secret_key_env']){const bad=config('namecheap');bad.providers[0][key]='PATH';assert.throws(()=>h.validateConfig(bad));}
});
test('Namecheap env-only fixed API options reject URLs literals namespaces and extra fields',()=>{
 const h=harness();for(const ref of ['NAMECHEAP_','DDNS_SERVER_IP','PATH','NAMECHEAP_lower','1.1.1.1','https://api.namecheap.com/xml.response','NAMECHEAP_'+'A'.repeat(55)]){const c=config('namecheap');c.providers[0].options.client_ip_env=ref;assert.throws(()=>h.validateConfig(c));}
 for(const [key,value] of [['scope','basicdns'],['write_mode','per_record'],['environment','auto'],['sld','example.com'],['sld','https://example'],['tld','.com'],['tld','averylongtld'],['endpoint','https://evil.invalid'],['EmailType','MX']]){const c=config('namecheap');c.providers[0].options[key]=value;assert.throws(()=>h.validateConfig(c));}
 const c=config('namecheap');c.providers[0].options.tld='co.uk';c.records[0].domain='example.co.uk';h.validateConfig(c);c.records[0].domain='home.example.co.uk';assert.throws(()=>h.validateConfig(c));
});
test('Namecheap logical ID format TTL and exact plain-line scope reject invalid native selection',()=>{
 const h=harness();for(const id of ['123','namecheap-'+'a'.repeat(63),'namecheap-'+'A'.repeat(64),'namecheap/123','..',123]){const c=config('namecheap');c.records[0].record_id=id;assert.throws(()=>h.validateConfig(c));}
 for(const ttl of [59,60001]){const c=config('namecheap');c.records[0].ttl=ttl;assert.throws(()=>h.validateConfig(c));}
 for(const line of ['telecom','Default',' default','default\n']){const c=config('namecheap');c.records[0].record_line=line;assert.throws(()=>h.validateConfig(c));}
 for(const line of ['','default','默认']){const c=config('namecheap');c.records[0].record_line=line;c.records[0].create_if_missing=true;h.validateConfig(c);const other=JSON.parse(JSON.stringify(c.records[0]));other.name='second';other.record_line='default';c.records.push(other);assert.throws(()=>h.validateConfig(c));}
 const c=config('namecheap');c.records[0].subdomain='';h.validateConfig(c);const other=JSON.parse(JSON.stringify(c.records[0]));other.name='second';other.subdomain='@';c.records.push(other);assert.throws(()=>h.validateConfig(c));
 const bad=config('namecheap');bad.records[0].options.proxied='true';assert.throws(()=>h.validateConfig(bad));
});
test('Namecheap bilingual whole-zone warnings explicit acknowledgement and logical ID controls visible',()=>{
 for(const locale of ['zh','en']){const h=harness(locale),c=config('namecheap');h.state.config=c;h.renderConfig();const all=text(h.elements.get('records'))+text(h.elements.get('providers'));for(const marker of ['Dynamic DNS','XML','exclusive_full_zone','HostCount','800','EmailType','OX','FWD','GMAIL','HostId','NAMECHEAP_','CAA','ALIAS','SRV','CAS'])assert.ok(all.includes(marker),marker);assert.ok(walk(h.elements.get('records')).some(e=>e.tagName==='input'&&e.value==='默认'&&e.disabled));assert.ok(walk(h.elements.get('records')).some(e=>e.type==='checkbox'&&!e.disabled&&!e.checked));assert.ok(walk(h.elements.get('providers')).some(e=>e.required&&e.value==='exclusive_full_zone'));}
});
test('Explicit switches to Namecheap clear acknowledgements IDs credentials options and old routing draft only',()=>{
 const h=harness(),c=config('trafficroute');c.records[0].record_line='telecom';c.records[0].record_id='123';c.records[0].options={zone_id:'old'};h.state.config=c;h.switchProviderKind(c.providers[0],'namecheap');assert.equal(c.records[0].record_line,'default');assert.equal(c.records[0].record_id,null);assert.deepEqual(Object.keys(c.records[0].options),[]);assert.deepEqual(Object.keys(c.providers[0].options),[]);assert.equal(c.providers[0].secret_id_env,'');assert.equal(c.providers[0].secret_key_env,'');assert.equal(c.records[0].enabled,false);assert.throws(()=>h.validateConfig(c));
 const h2=harness(),c2=config('trafficroute');const nc=config('namecheap').providers[0];nc.name='other';c2.providers.push(nc);h2.state.config=c2;h2.renderConfig();const selector=walk(h2.elements.get('records')).find(e=>e.dataset.providerIndex==='0');selector.value='other';selector.events.change();assert.equal(c2.records[0].record_line,'default');assert.equal(c2.records[0].record_id,null);
});

const sentinel = '__DDNS_CONFIGURED__';
const response = (data,status=200) => ({ok:status>=200&&status<300,status,async text(){return data===null?'':JSON.stringify(data);}});
function fetchQueue(...replies) {const calls=[];const fetch=async(url,options)=>{calls.push({url,options});assert.ok(replies.length,`Unexpected fetch: ${url}`);const reply=replies.shift();if(reply instanceof Error)throw reply;return typeof reply==='function'?reply(url,options):reply;};return {fetch,calls};}
const settings = (extra={}) => ({listen:'127.0.0.1:8080',active_listen:'127.0.0.1:8080',username:'admin',token_configured:false,...extra});

test('account setup trims usernames, confirms password and enforces backend UTF-8 byte bounds',()=>{
  for(const locale of ['zh','en']) {const h=harness(locale);assert.equal(h.validateAccount(' admin ','password','password').username,'admin');
    for(const username of [' ', 'x'.repeat(65),'界'.repeat(22)])assert.throws(()=>h.validateAccount(username,'password','password'));
    for(const password of ['1234567','x'.repeat(129),'界'.repeat(43)])assert.throws(()=>h.validateAccount('admin',password,password));
    h.validateAccount('界'.repeat(21),'界界界','界界界');assert.throws(()=>h.validateAccount('admin','password','different'));
  }
});
test('auth starts loading and does not flash setup; status failure can recover',async()=>{
  let resolve;const pending=new Promise(r=>resolve=r),calls=[];
  const h=harness('en',async(url,options)=>{calls.push({url,options});return pending;});h.renderAuth();
  assert.equal(h.state.authMode,'loading');assert.equal(h.elements.get('authForm').hidden,true);
  const checking=h.checkAuth();assert.equal(h.elements.get('authForm').hidden,true);resolve(response({initialized:false}));await checking;
  assert.equal(h.state.authMode,'setup');assert.equal(h.elements.get('confirmPassword').required,true);assert.deepEqual(calls.map(c=>c.url),['/api/auth/status']);assert.equal(calls[0].options.credentials,'same-origin');assert.ok(!calls[0].options.headers.Authorization);
  const q=fetchQueue(new TypeError('offline'),response({initialized:false})),retry=harness('en',q.fetch);await retry.checkAuth();assert.equal(retry.state.authMode,'error');assert.equal(retry.elements.get('authRetry').hidden,false);await retry.checkAuth();assert.equal(retry.state.authMode,'setup');
});
test('status precedes config cookie resume, and unauthenticated resume shows login without config',async()=>{
  const q=fetchQueue(response({initialized:true}),response({message:'unauthorized'},401)),h=harness('en',q.fetch);await h.checkAuth();
  assert.deepEqual(q.calls.map(c=>c.url),['/api/auth/status','/api/config']);assert.equal(h.state.authMode,'login');assert.equal(h.state.authenticated,false);assert.equal(h.state.config,null);assert.equal(h.elements.get('configFields').disabled,true);assert.equal(h.elements.get('confirmPasswordLabel').hidden,true);
});
test('valid cookie resumes full existing console and actual protected settings',async()=>{
  const interfaces=[{name:'eth0',ipv4:['1.1.1.1'],ipv6:[]}];
  const q=fetchQueue(response({initialized:true}),response(config()),response(registry),response(interfaces),response({running:false,last_run:null}),response([]),response(settings())),h=harness('en',q.fetch);await h.checkAuth();
  assert.equal(h.state.authenticated,true);assert.equal(h.elements.get('authForm').hidden,true);assert.equal(h.elements.get('settingsUsername').value,'admin');assert.equal(h.elements.get('settingsFields').disabled,false);assert.ok(q.calls.every(c=>c.options.credentials==='same-origin' && !c.options.headers.Authorization));
  assert.ok(q.calls.some(c=>c.url==='/api/interfaces'));
  assert.equal(h.state.interfaces[0].name,'eth0');
});
test('setup conflict and uncertain setup network success recover to login and wipe passwords',async()=>{
  for(const replies of [[response({message:'already initialized'},409)],[new TypeError('offline'),response({initialized:true})]]) {
    const q=fetchQueue(...replies),h=harness('en',q.fetch);h.state.authMode='setup';h.elements.get('username').value=' admin ';h.elements.get('password').value='password';h.elements.get('confirmPassword').value='password';await h.connect({preventDefault(){}});
    assert.equal(h.state.authMode,'login');assert.equal(h.state.initialized,true);assert.equal(h.elements.get('password').value,'');assert.equal(h.elements.get('confirmPassword').value,'');assert.deepEqual(JSON.parse(q.calls[0].options.body),{username:'admin',password:'password'});
  }
});
test('account setup response username and cookie session are used without persisting a bearer',async()=>{
  const q=fetchQueue(response({username:'actual-admin'}),response(registry),response([]),response(config()),response({running:false,last_run:null}),response([]),response(settings({username:'actual-admin'}))),h=harness('en',q.fetch);h.state.authMode='setup';h.elements.get('username').value=' admin ';h.elements.get('password').value='password';h.elements.get('confirmPassword').value='password';await h.connect({preventDefault(){}});
  assert.equal(h.state.authenticated,true);assert.equal(h.elements.get('username').value,'actual-admin');assert.equal(h.state.token,'');assert.equal(h.elements.get('password').value,'');assert.equal(q.calls[0].url,'/api/auth/setup');
});
test('direct credential alternatives accept sentinels but retain all explicit provider safety acknowledgements',()=>{
  const h=harness();for(const kind of ['namecheap','trafficroute','callback','huaweicloud','baiducloud','edgeone','hipmdnsmgr','dynv6','spaceship','gcore','namesilo']) {
    const c=config(kind),p=c.providers[0],d=registry.find(d=>d.kind===kind);p.credentials={};for(const f of d.credential_fields){p[f.key]='';p.credentials[f.key]=sentinel;}
    for(const f of d.options.filter(f=>['endpoint_env','client_ip_env'].includes(f.key))){p.options[f.key]='';p.credentials[f.key]=sentinel;}
    h.validateConfig(c);for(const f of d.options.filter(f=>f.required && !['endpoint_env','client_ip_env'].includes(f.key))){const bad=JSON.parse(JSON.stringify(c));delete bad.providers[0].options[f.key];assert.throws(()=>h.validateConfig(bad),`${kind}:${f.key}`);}
    const bad=JSON.parse(JSON.stringify(c));bad.providers[0].credentials.endpoint='https://evil.invalid';assert.throws(()=>h.validateConfig(bad));
  }
});
test('configured direct password controls are blank; edit drafts never enter state, JSON or export mask',()=>{
  for(const locale of ['zh','en']) {const h=harness(locale),c=config('spaceship');c.providers[0].credentials={secret_id_env:sentinel,secret_key_env:sentinel};h.state.config=c;h.renderConfig();
    const inputs=walk(h.elements.get('providers')).filter(e=>e.dataset.directCredential);assert.equal(inputs.length,2);assert.ok(inputs.every(e=>e.type==='password'&&e.value===''&&e.placeholder.includes(locale==='zh'?'已配置':'Configured')));
    assert.deepEqual(inputs.map(e=>e.parentNode.children[0].textContent),locale==='zh'?['凭据 ID','凭据 Secret']:['Credential ID','Credential Secret']);
    const secret='never-export-this-secret';inputs[1].value=secret;inputs[1].events.input();assert.equal(c.providers[0].credentials.secret_key_env,sentinel);assert.equal(h.configPayload(c).providers[0].credentials.secret_key_env,secret);
    h.elements.get('jsonDetails').open=true;h.elements.get('jsonDetails').events.toggle();assert.ok(!h.elements.get('configJson').value.includes(secret));assert.ok(!JSON.stringify(h.maskedConfig(c)).includes(secret));
    inputs[1].value='';inputs[1].events.input();assert.equal(h.configPayload(c).providers[0].credentials.secret_key_env,'');assert.equal(c.providers[0].credentials.secret_key_env,sentinel);
  }
});
test('JSON editor rejects raw direct credentials, and switching provider discards write-only drafts',()=>{
  const h=harness('en'),c=config('spaceship');h.state.config=c;h.renderConfig();const input=walk(h.elements.get('providers')).find(e=>e.dataset.directCredential==='secret_key_env');input.value='draft-secret';input.events.input();
  const pasted=config('spaceship');pasted.providers[0].credentials={secret_key_env:'pasted-secret'};h.elements.get('configJson').value=JSON.stringify(pasted);h.elements.get('applyJson').events.click();assert.equal(h.state.config,c);assert.match(h.elements.get('notice').textContent,/redaction markers/);
  h.switchProviderKind(c.providers[0],'dynv6');assert.equal(c.providers[0].credentials,undefined);assert.ok(!JSON.stringify(h.configPayload(c)).includes('draft-secret'));
});
test('config save consumes actual redacted PUT response and wipes direct password fields',async()=>{
  const actual=config('spaceship');actual.interval_secs=600;actual.providers[0].credentials={secret_key_env:sentinel};const q=fetchQueue(response(actual)),h=harness('en',q.fetch);h.state.config=config('spaceship');h.state.authenticated=true;h.renderConfig();const input=walk(h.elements.get('providers')).find(e=>e.dataset.directCredential==='secret_key_env');input.value='new-secret';input.events.input();await h.elements.get('saveConfig').events.click();
  assert.equal(JSON.parse(q.calls[0].options.body).providers[0].credentials.secret_key_env,'new-secret');assert.equal(h.state.config.interval_secs,600);assert.equal(h.state.config.providers[0].credentials.secret_key_env,sentinel);assert.ok(walk(h.elements.get('providers')).filter(e=>e.dataset.directCredential).every(e=>e.value===''));assert.equal(q.calls.length,1);
});
test('settings consume actual responses, restart notice, explicit empty-token disable and account relogin',async()=>{
  for(const kind of ['listen','username','password','token']) {const actual=settings({listen:'127.0.0.1:9090',username:kind==='username'?'renamed':'admin'}),q=fetchQueue(response(actual)),h=harness('en',q.fetch);h.state.authenticated=true;h.state.initialized=true;h.acceptSettings(settings());
    h.elements.get('settingsListen').value='127.0.0.1:9090';if(kind==='username')h.elements.get('settingsUsername').value='renamed';if(kind==='password')h.elements.get('settingsPassword').value='new-password';if(kind==='token'){h.elements.get('changeToken').checked=true;h.elements.get('settingsToken').value='';}
    await h.elements.get('settingsForm').events.submit({preventDefault(){}});const payload=JSON.parse(q.calls[0].options.body);assert.equal(payload.token,kind==='token'?'':undefined);assert.equal(payload.password,kind==='password'?'new-password':undefined);assert.match(h.elements.get('notice').textContent,/127.0.0.1:9090/);assert.match(h.elements.get('notice').textContent,/restart/);assert.equal(h.state.authenticated,kind==='listen');assert.equal(h.elements.get('settingsPassword').value,'');assert.equal(h.elements.get('settingsToken').value,'');
  }
});
test('logout clears session server-side, console state, JSON and all password drafts',async()=>{
  const q=fetchQueue(response(null,204)),h=harness('en',q.fetch);h.state.config=config('spaceship');h.state.authenticated=true;h.state.initialized=true;h.renderConfig();const input=walk(h.elements.get('providers')).find(e=>e.dataset.directCredential);input.value='logout-secret';input.events.input();h.elements.get('password').value='password';await h.logout();assert.equal(q.calls[0].url,'/api/auth/logout');assert.equal(q.calls[0].options.method,'POST');assert.equal(h.state.authenticated,false);assert.equal(h.state.config,null);assert.equal(h.elements.get('configJson').value,'');assert.equal(h.elements.get('password').value,'');assert.equal(input.value,'');
});

test('password login posts to login endpoint and rejected login remains retryable without console access',async()=>{
  const q=fetchQueue(response({message:'bad password'},401)),h=harness('en',q.fetch);h.state.authMode='login';h.state.initialized=true;h.elements.get('username').value=' admin ';h.elements.get('password').value='wrong-password';await h.connect({preventDefault(){}});assert.equal(q.calls[0].url,'/api/auth/login');assert.deepEqual(JSON.parse(q.calls[0].options.body),{username:'admin',password:'wrong-password'});assert.equal(h.state.authMode,'login');assert.equal(h.state.authenticated,false);assert.equal(h.state.connecting,false);assert.equal(h.elements.get('password').value,'');assert.equal(h.elements.get('configFields').disabled,true);
});
test('protected API unauthorized response revokes console and masks; legacy bearer remains optional',async()=>{
  const q=fetchQueue(response({message:'expired'},401)),h=harness('en',q.fetch);h.state.config=config();h.state.authenticated=true;h.state.initialized=true;h.state.token='optional-legacy';h.renderConfig();await assert.rejects(h.api('/api/config'));assert.equal(q.calls[0].options.headers.Authorization,'Bearer optional-legacy');assert.equal(h.state.authenticated,false);assert.equal(h.state.config,null);assert.equal(h.state.token,'');assert.equal(h.elements.get('configFields').disabled,true);
});
test('failed settings save wipes passwords but preserves unsaved provider credential drafts',async()=>{
  const q=fetchQueue(response({message:'remove CLI token override and restart'},409)),h=harness('en',q.fetch);h.state.authenticated=true;h.state.config=config('spaceship');h.renderConfig();h.acceptSettings(settings());const input=walk(h.elements.get('providers')).find(e=>e.dataset.directCredential==='secret_key_env');input.value='unsaved-provider-secret';input.events.input();h.elements.get('settingsPassword').value='new-password';h.elements.get('changeToken').checked=true;h.elements.get('settingsToken').value='new-token';await h.elements.get('settingsForm').events.submit({preventDefault(){}});assert.equal(h.state.authenticated,true);assert.equal(h.elements.get('settingsPassword').value,'');assert.equal(h.elements.get('settingsToken').value,'');assert.equal(h.configPayload(h.state.config).providers[0].credentials.secret_key_env,'unsaved-provider-secret');assert.match(h.elements.get('notice').textContent,/remove CLI token override/);
});
