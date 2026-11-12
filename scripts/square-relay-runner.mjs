import {createHash,randomUUID} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {signRelayRequest} from '../src/shared/relay-auth.mjs';

export const RELAY_REPOSITORY='a280395589/crypto-dragon-square-relay';
export const SQUARE_V1='https://www.binance.com/bapi/composite/v1/public/pgc/openApi';
export const SQUARE_V2='https://www.binance.com/bapi/composite/v2/public/pgc/openApi';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH=/^[0-9a-fA-F]{64}$/;
const MAX_MEDIA_BYTES=1048576,MAX_PROVIDER_BYTES=65536,MAX_CLAIM_BYTES=1450000;
const sha=value=>createHash('sha256').update(value).digest('hex').toUpperCase();
const stop=code=>{throw Object.assign(new Error(code),{safeCode:code});};
const plain=value=>Boolean(value&&typeof value==='object'&&!Array.isArray(value));
const errorCode=error=>/^SQUARE_RELAY_[A-Z_]+$/.test(error?.safeCode??'')?error.safeCode:'SQUARE_RELAY_REQUEST_FAILED';

export function validateRelayOrigin(origin,hostname){
  if(typeof origin!=='string'||typeof hostname!=='string'||!/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2}workers\.dev$/.test(hostname))stop('SQUARE_RELAY_ORIGIN_INVALID');
  let url;try{url=new URL(origin);}catch{stop('SQUARE_RELAY_ORIGIN_INVALID');}
  if(url.protocol!=='https:'||url.username||url.password||url.port||url.search||url.hash||url.pathname!=='/'||url.hostname!==hostname)stop('SQUARE_RELAY_ORIGIN_INVALID');
  return url.origin;
}

// Upload URLs are delegated by the authenticated Binance endpoint. Only its
// documented storage/CDN domain families are accepted; never follow redirects.
export function validateSquareMediaUrl(value,{upload=false}={}){
  if(typeof value!=='string'||value.length>8192)stop('SQUARE_RELAY_MEDIA_URL_INVALID');
  let url;try{url=new URL(value);}catch{stop('SQUARE_RELAY_MEDIA_URL_INVALID');}
  const host=url.hostname;
  const cdn=/(^|\.)bnbstatic\.com$/.test(host);
  const providerUpload=upload&&/(^|\.)binance\.com$/.test(host);
  const storage=/(^|\.)s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com(?:\.cn)?$/.test(host);
  if(url.protocol!=='https:'||url.username||url.password||url.port||url.hash||(!upload&&url.search)||!/^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)||!(cdn||providerUpload||(upload&&storage)))stop('SQUARE_RELAY_MEDIA_URL_UNTRUSTED');
  return url.href;
}

function identity(env){
  if(env.GITHUB_REPOSITORY!==RELAY_REPOSITORY||env.GITHUB_ACTIONS!=='true')stop('SQUARE_RELAY_REPOSITORY_INVALID');
  if(typeof env.JOB_ID!=='string'||!UUID.test(env.JOB_ID))stop('SQUARE_RELAY_JOB_ID_INVALID');
  if(!/^[1-9][0-9]{0,23}$/.test(env.GITHUB_RUN_ID??'')||env.GITHUB_RUN_ATTEMPT!=='1')stop('SQUARE_RELAY_RUN_ID_INVALID');
  return {job_id:env.JOB_ID,repository:RELAY_REPOSITORY,run_id:env.GITHUB_RUN_ID,run_attempt:Number(env.GITHUB_RUN_ATTEMPT)};
}
function credential(env,{optional=false}={}){
  const value=env.CCA_BINANCE_SQUARE_POST_KEY;
  if(optional&&(value===undefined||value===''))return null;
  if(typeof value!=='string'||!value.trim()||value.length>4096||/[\r\n]/.test(value))stop('SQUARE_RELAY_CREDENTIAL_INVALID');
  return value.trim();
}
function headers(key){return {'Content-Type':'application/json',Accept:'application/json',clienttype:'binanceSkill','User-Agent':'CryptoDragon/1.0 (Binance Square OpenAPI)',...(key?{'X-Square-OpenAPI-Key':key}:{})};}
function dependencies(options){return {fetch:options.fetch??globalThis.fetch,now:options.now??Date.now,wait:options.wait??delay,nonce:options.nonce??randomUUID};}
function fresh(job,now){if(Date.parse(job.expires_utc)<=now())stop('SQUARE_RELAY_JOB_EXPIRED');}

export function validateRelayJob(value,expected,{now=Date.now,credentialSha256}={}){
  if(!plain(value)||value.job_id!==expected.job_id||!/^queue_[0-9a-f-]{36}$/.test(value.queue_id??''))stop('SQUARE_RELAY_JOB_MISMATCH');
  for(const field of ['publication_key','event_fingerprint','content_sha256','credential_sha256'])if(typeof value[field]!=='string'||!HASH.test(value[field]))stop('SQUARE_RELAY_JOB_MISMATCH');
  if(typeof value.text!=='string'||!value.text.trim()||value.text.length>10000||Buffer.byteLength(value.text,'utf8')>16384||sha(value.text)!==value.content_sha256.toUpperCase()||value.credential_sha256.toUpperCase()!==credentialSha256)stop('SQUARE_RELAY_JOB_INTEGRITY_FAILED');
  if(typeof value.expires_utc!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value.expires_utc)||!Number.isFinite(Date.parse(value.expires_utc)))stop('SQUARE_RELAY_JOB_EXPIRED');
  fresh(value,now);
  let media;
  if(value.media!==undefined&&value.media!==null){
    const m=value.media;
    if(!plain(m)||!['image/png','image/jpeg'].includes(m.mime_type)||!HASH.test(m.sha256??'')||typeof m.base64!=='string'||m.base64.length>Math.ceil(MAX_MEDIA_BYTES/3)*4||!m.base64||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(m.base64))stop('SQUARE_RELAY_MEDIA_INVALID');
    const bytes=Buffer.from(m.base64,'base64');
    const png=bytes.length>=8&&Buffer.from([137,80,78,71,13,10,26,10]).equals(bytes.subarray(0,8));
    const jpeg=bytes.length>=4&&bytes[0]===255&&bytes[1]===216&&bytes[2]===255;
    if(!bytes.length||bytes.length>MAX_MEDIA_BYTES||bytes.toString('base64')!==m.base64||sha(bytes)!==m.sha256.toUpperCase()||(m.mime_type==='image/png'?!png:!jpeg))stop('SQUARE_RELAY_MEDIA_INTEGRITY_FAILED');
    media=Object.freeze({bytes,mime_type:m.mime_type,sha256:m.sha256.toUpperCase()});
  }
  return Object.freeze({job_id:value.job_id,queue_id:value.queue_id,publication_key:value.publication_key,event_fingerprint:value.event_fingerprint,content_sha256:value.content_sha256.toUpperCase(),credential_sha256:value.credential_sha256.toUpperCase(),text:value.text,expires_utc:value.expires_utc,...(media?{media}:{})});
}

async function readBounded(response,maxBytes){
  const reader=response.body?.getReader();const chunks=[];let length=0;
  if(reader){try{while(true){const {done,value}=await reader.read();if(done)break;length+=value.byteLength;if(length>maxBytes){await reader.cancel();stop('SQUARE_RELAY_RESPONSE_TOO_LARGE');}chunks.push(Buffer.from(value));}}finally{reader.releaseLock();}}
  const bytes=Buffer.concat(chunks);let data;try{data=JSON.parse(bytes.toString('utf8'));}catch{}
  return {data,response_sha256:sha(bytes)};
}
function providerCode(data){return typeof data?.code==='string'&&/^[A-Z0-9_-]{1,64}$/.test(data.code)?data.code:null;}
function remoteId(value){if(typeof value==='string'&&/^[1-9][0-9]{0,39}$/.test(value))return value;if(Number.isSafeInteger(value)&&value>0)return String(value);return null;}

async function gatewayCall(config,path,payload,deps,{maxBytes=MAX_PROVIDER_BYTES}={}){
  const body=JSON.stringify(payload);
  const auth=await signRelayRequest({secret:config.secret,path,body,nonce:deps.nonce(),timestamp:Math.floor(deps.now()/1000),method:'POST'});
  const response=await deps.fetch(config.origin+path,{method:'POST',redirect:'manual',headers:{...auth,'Content-Type':'application/json',Accept:'application/json'},body,signal:AbortSignal.timeout(20000)});
  const parsed=await readBounded(response,maxBytes);
  return {status:response.status,ok:response.ok&&!response.redirected&&parsed.data?.ok===true,data:parsed.data};
}
async function acknowledge(config,result,deps){
  for(let attempt=0;attempt<3;attempt++){
    try{const response=await gatewayCall(config,'/v1/square-relay/result',result,deps);if(response.ok)return true;if(response.status<500&&response.status!==429)return false;}catch{}
    if(attempt<2)await deps.wait(1000*(attempt+1));
  }
  return false;
}
async function squareApi(path,key,body,deps){
  const response=await deps.fetch(SQUARE_V2+path,{method:'POST',redirect:'manual',headers:headers(key),body:JSON.stringify(body),signal:AbortSignal.timeout(15000)});
  const parsed=await readBounded(response,MAX_PROVIDER_BYTES);
  if(!response.ok||response.redirected||parsed.data?.code!=='000000'||!plain(parsed.data.data))stop('SQUARE_RELAY_MEDIA_PROVIDER_REJECTED');
  return parsed.data.data;
}
async function uploadMedia(job,key,deps){
  fresh(job,deps.now);
  const imageName=job.media.sha256.toLowerCase()+(job.media.mime_type==='image/png'?'.png':'.jpg');
  const signed=await squareApi('/image/presignedUrl',key,{imageName},deps);
  const url=validateSquareMediaUrl(signed.presignedUrl,{upload:true});
  if(typeof signed.fileTicket!=='string'||!signed.fileTicket.trim()||signed.fileTicket.length>2048||/[\r\n]/.test(signed.fileTicket))stop('SQUARE_RELAY_MEDIA_TICKET_INVALID');
  fresh(job,deps.now);
  // No Binance credential, HMAC headers, or retries on the delegated upload.
  const uploaded=await deps.fetch(url,{method:'PUT',redirect:'manual',headers:{'Content-Type':job.media.mime_type},body:job.media.bytes,signal:AbortSignal.timeout(20000)});
  if(!uploaded.ok||uploaded.redirected)stop('SQUARE_RELAY_MEDIA_UPLOAD_UNCONFIRMED');
  await uploaded.body?.cancel();
  for(let attempt=0;attempt<5;attempt++){
    fresh(job,deps.now);
    const state=await squareApi('/image/imageStatus',key,{fileTicket:signed.fileTicket},deps);
    if(state.status===1)return validateSquareMediaUrl(state.imageUrl);
    if(state.status!==0)stop('SQUARE_RELAY_MEDIA_PROCESSING_FAILED');
    if(attempt<4)await deps.wait(1000);
  }
  stop('SQUARE_RELAY_MEDIA_PROCESSING_PENDING');
}

export async function runSquareRelay(env,options={}){
  const deps=dependencies(options),run=identity(env),key=credential(env);
  const secret=env.CCA_SQUARE_RELAY_SECRET;
  if(typeof secret!=='string'||Buffer.byteLength(secret,'utf8')<32||Buffer.byteLength(secret,'utf8')>4096)stop('SQUARE_RELAY_SECRET_INVALID');
  const config={origin:validateRelayOrigin(env.CCA_SQUARE_RELAY_ORIGIN,env.CCA_SQUARE_RELAY_HOSTNAME),secret};
  const credentialSha256=sha(key);
  const claim=await gatewayCall(config,'/v1/square-relay/claim',{...run,credential_sha256:credentialSha256},deps,{maxBytes:MAX_CLAIM_BYTES});
  if(!claim.ok)stop('SQUARE_RELAY_CLAIM_REJECTED');
  const job=validateRelayJob(claim.data.job,run,{now:deps.now,credentialSha256});
  const result={...run,content_sha256:job.content_sha256,permit_id:null,outcome:'NO_CONTENT_ATTEMPT',http_status:null,provider_code:null,remote_id:null,response_sha256:null,error_code:null};
  let contentAttempted=false;
  try{
    const imageUrl=job.media?await uploadMedia(job,key,deps):null;
    fresh(job,deps.now);
    const armed=await gatewayCall(config,'/v1/square-relay/arm',{...run,content_sha256:job.content_sha256,...(imageUrl?{image_url:imageUrl}:{})},deps);
    if(!armed.ok||armed.data.publish_authorized!==true||!UUID.test(armed.data.permit_id??''))stop('SQUARE_RELAY_ARM_NOT_AUTHORIZED');
    result.permit_id=armed.data.permit_id;
    fresh(job,deps.now);
    const payload={contentType:1,bodyTextOnly:job.text,...(imageUrl?{imageList:[imageUrl]}:{})};
    // From this point every unconfirmed result is UNKNOWN. Exactly one fetch;
    // no retry, redirect, browser automation, or second content/add invocation.
    contentAttempted=true;result.outcome='UNKNOWN';
    const response=await deps.fetch(SQUARE_V1+'/content/add',{method:'POST',redirect:'manual',headers:headers(key),body:JSON.stringify(payload),signal:AbortSignal.timeout(35000)});
    result.http_status=response.status;
    const parsed=await readBounded(response,MAX_PROVIDER_BYTES);
    result.response_sha256=parsed.response_sha256;result.provider_code=providerCode(parsed.data);
    const id=remoteId(parsed.data?.data?.id);
    if(response.ok&&!response.redirected&&result.provider_code==='000000'&&id){result.outcome='DELIVERED';result.remote_id=id;}
    else result.error_code='SQUARE_RELAY_CONTENT_UNCONFIRMED';
  }catch(error){result.outcome=contentAttempted?'UNKNOWN':'NO_CONTENT_ATTEMPT';result.error_code=errorCode(error);}
  const acknowledged=await acknowledge(config,result,deps);
  return {status:acknowledged?result.outcome:'RESULT_UNCONFIRMED',acknowledged,outcome:result.outcome,remote_id:result.remote_id};
}

export async function runSquareProbe(env={},options={}){
  const deps=dependencies(options),key=credential(env,{optional:true});
  try{
    const response=await deps.fetch(SQUARE_V2+'/image/imageStatus',{method:'POST',redirect:'manual',headers:headers(key),body:JSON.stringify({fileTicket:'cca-read-only-connectivity-no-upload'}),signal:AbortSignal.timeout(15000)});
    const parsed=await readBounded(response,MAX_PROVIDER_BYTES),code=providerCode(parsed.data);
    return {status:code?'API_RESPONSE':'NO_API_RESPONSE',http_status:response.status,provider_code:code,send:false,upload:false};
  }catch{return {status:'PROBE_UNCONFIRMED',http_status:null,provider_code:null,send:false,upload:false};}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{
    const args=process.argv.slice(2),mode=process.env.CCA_SQUARE_RELAY_MODE??'publish';
    if(args.length>1||(args.length===1&&args[0]!=='--probe')||!['probe','publish'].includes(mode))stop('SQUARE_RELAY_MODE_INVALID');
    const probe=args[0]==='--probe'||mode==='probe';
    const outcome=probe?await runSquareProbe(process.env):await runSquareRelay(process.env);
    console.log(`SQUARE_RELAY_STATUS=${outcome.status}`);
    if(probe){console.log(`SQUARE_PROBE_HTTP_STATUS=${outcome.http_status??'unknown'}`);console.log(`SQUARE_PROBE_PROVIDER_CODE=${outcome.provider_code??'unknown'}`);}
    else if(outcome.acknowledged&&outcome.outcome==='DELIVERED')console.log(`SQUARE_CONFIRMED_POST_ID=${outcome.remote_id}`);
    process.exitCode=probe?0:(outcome.acknowledged&&outcome.outcome==='DELIVERED'?0:1);
  }catch{console.log('SQUARE_RELAY_STATUS=STOPPED');process.exitCode=1;}
}
