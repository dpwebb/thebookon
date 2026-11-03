'use strict';
const test=require('node:test'), assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
test('real intake routes queue only successful receipts and omit private content',async t=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'book-notification-http-'));
 const prior={...process.env};
 Object.assign(process.env,{NODE_ENV:'test',DATA_DIR:path.join(directory,'data'),SESSION_SECRET:'local-only-synthetic-session-secret',NOTIFICATIONS_MODE:'capture',NOTIFICATIONS_DIRECTORY:path.join(directory,'outbox'),NOTIFICATIONS_ENCRYPTION_KEY:'a'.repeat(64)});
 const {app}=require('../server.js'),{notifications}=require('./project.cjs');
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
 t.after(async()=>{await new Promise(resolve=>server.close(resolve));await notifications.close();process.env=prior;if(path.dirname(directory)!==fs.realpathSync(os.tmpdir()))throw Error('Unexpected test directory');fs.rmSync(directory,{recursive:true,force:true});});
 const origin=`http://127.0.0.1:${server.address().port}`;
 const post=(route,body)=>fetch(origin+route,{method:'POST',body:new URLSearchParams(body),redirect:'manual'});
 assert.equal((await post('/api/contact',{name:'Test',email:'bad',message:'private inquiry'})).status,400);
 assert.equal((await post('/api/register',{full_name:'Test',email:'writer@example.invalid',password:'short',confirm_password:'short'})).status,400);
 const registration=await post('/api/register',{full_name:'Test',email:'writer@example.invalid',password:'fixture-secret-123',confirm_password:'fixture-secret-123'});
 assert.equal(registration.status,303);
 const cookie=registration.headers.get('set-cookie').split(';')[0];
 assert.equal((await post('/api/register',{full_name:'Test',email:'writer@example.invalid',password:'fixture-secret-123',confirm_password:'fixture-secret-123'})).status,409);
 assert.equal((await post('/api/contact',{name:'Test',email:'writer@example.invalid',message:'private inquiry'})).status,200);
 const form=new FormData();
 for(const [k,v] of Object.entries({author_name:'Test',email:'writer@example.invalid',title:'Private title',category:'Fiction',stage:'Draft',service_interest:'Review',audience:'Readers',synopsis:'private synopsis',rights_confirm:'yes',terms_confirm:'yes'}))form.set(k,v);
 form.set('manuscript_file',new Blob(['private manuscript'],{type:'text/plain'}),'fixture.txt');
 assert.equal((await fetch(origin+'/api/manuscripts',{method:'POST',headers:{cookie},body:form,redirect:'manual'})).status,200);
 await post('/api/password-reset',{email:'unknown@example.invalid'});
 await post('/api/password-reset',{email:'writer@example.invalid'});
 for(let i=0;i<10;i++)await notifications.dispatch();
 const captures=notifications.captures();assert.equal(captures.length,6);
 assert.equal(captures.filter(m=>m.to==='writer@example.invalid').length,3);
 assert.equal(captures.filter(m=>m.to==='admin@thebookon.ca').length,3);
 assert.ok(captures.every(m=>m.from==='admin@thebookon.ca'));
 const output=JSON.stringify(captures);for(const privateText of ['private inquiry','private synopsis','private manuscript','fixture-secret-123','unknown@example.invalid'])assert.ok(!output.includes(privateText),privateText);
 const dashboard=async()=> (await (await fetch(origin+'/api/session',{headers:{cookie}})).json()).submissions[0];
 const original=await dashboard();
 assert.equal(original.status,'Pending');
 assert.equal((await post('/api/manuscripts/withdrawal',{id:original.id})).status,303);
 assert.equal((await dashboard()).withdrawalState,null);
 const request=()=>fetch(origin+'/api/manuscripts/withdrawal',{
  method:'POST',headers:{cookie},body:new URLSearchParams({id:original.id}),redirect:'manual'
 });
 assert.equal((await request()).status,303);
 assert.equal((await request()).status,303);
 assert.equal((await dashboard()).withdrawalState,'requested');
 assert.equal((await post('/internal/editorial/withdrawal',{id:original.id})).status,404);
 const {promisify}=require('node:util');
 const execFile=promisify(require('node:child_process').execFile);
 const editorial=async()=>JSON.parse((await execFile(process.execPath,[
  path.join(__dirname,'../scripts/editorial-withdrawal.cjs'),original.id,'--verified-pre-agreement'
 ],{env:{...process.env,PORT:String(server.address().port)}})).stdout);
 assert.equal((await editorial()).status,'Withdrawn');
 const outcome=await dashboard();
 assert.equal(outcome.status,'Withdrawn');
 assert.equal(outcome.reviewState,'Closed');
 assert.equal(outcome.withdrawalState,'confirmed');
 await editorial();
 assert.equal((await dashboard()).updatedAt,outcome.updatedAt);
 for(let i=0;i<5;i++)await notifications.dispatch();
 const messages=notifications.captures();
 assert.equal(messages.filter(m=>m.subject==='A manuscript withdrawal needs editorial review').length,1);
 const confirmations=messages.filter(m=>m.subject==='Your manuscript withdrawal is confirmed');
 assert.equal(confirmations.length,1);
 assert.equal(confirmations[0].to,'writer@example.invalid');
 assert.ok(JSON.stringify(confirmations[0]).includes(original.id));
 assert.ok(!JSON.stringify(confirmations[0]).includes('Private title'));

});
