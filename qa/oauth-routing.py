#!/usr/bin/python3
"""Exercise callback restoration through startup and live URL delivery."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

spec = importlib.util.spec_from_file_location(
    'patcher', Path(__file__).resolve().parents[1] / 'engine/patch-deep-link.py')
patcher = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = patcher
spec.loader.exec_module(patcher)

# Build 12776: registration moved into a function with an early-return guard;
# a browser-handoff listener now separates open-url registration from the drain.
PREVIOUS = b'function T(){if(!t)return;let n=(e,t)=>{let n=n9(e);if(n){g(n),u?.(a9(n,e)),t?.preventDefault();return}let r=f9(e);r&&(_(r),t?.preventDefault())};e.on(`open-url`,(e,t)=>{n(t,e)}),d.l(e,(e,t)=>(g(t),u?.(void 0),!0));for(let e of d.s())n(e)}'
# Build 20770 adds a callback guard for background thread wakeups.
CURRENT = PREVIOUS.replace(b'g(n),u?.', b'g(n),n.kind!==`wakeQueuedThread`&&u?.')


def run_javascript(javascript):
    swift = '''import Foundation
import JavaScriptCore
let context = JSContext()!
var failed = false
context.exceptionHandler = { _, error in
    failed = true
    print(error?.toString() ?? "JavaScript exception")
}
let script = String(data: FileHandle.standardInput.readDataToEndOfFile(), encoding: .utf8)!
var result = context.evaluateScript(script)
if let asyncResult = context.objectForKeyedSubscript("doppelTestResult"), !asyncResult.isUndefined {
    result = asyncResult
}
if failed || result?.toString() != "PASS" {
    print(result?.toString() ?? "No JavaScript result")
    exit(1)
}
'''
    return subprocess.run(['/usr/bin/swift', '-e', swift], input=javascript,
                          text=True, capture_output=True, timeout=90)


class RoutingTests(unittest.TestCase):
    def test_current_handler_behavior(self):
        self.exercise_handler(CURRENT, wake_callback=False)

    def test_previous_handler_behavior(self):
        self.exercise_handler(PREVIOUS, wake_callback=True)

    def exercise_handler(self, sample, wake_callback):
        matches = list(patcher.DRAINED_OPEN_URL_HANDLER.finditer(sample))
        self.assertEqual(len(matches), 1)
        match = matches[0]
        patched = (sample[:match.start()] + patcher.patched_drained_open_url_handler(match)
                   + sample[match.end():]).decode()
        # Execute the actual replacement in macOS's JavaScriptCore. No Node
        # install, OAuth request, or real protocol ownership change is needed.
        javascript = r'''
const results = [];
function check(value, message) { if (!value) throw Error(message); }
function exercise(enabled) {
  let t=enabled, listener=null, handoff=null, spawned=[], queued=[], callbacks=[], http=[];
  let e={on:(name,fn)=>{check(name==='open-url','event name');listener=fn;}};
  let d={l:(app,fn)=>{check(app===e,'handoff app');handoff=fn;},s:()=>['oauth']};
  let g=route=>queued.push(route.kind), u=url=>callbacks.push(url);
  let n9=url=>url==='oauth'?{kind:'connectorOAuthCallback'}:url==='thread'?{kind:'thread'}:url==='wake'?{kind:'wakeQueuedThread'}:null;
  let a9=(route,url)=>url, f9=url=>url==='https://example.test'?url:null, _=url=>http.push(url);
  let process={env:{DOPPEL_URL_HANDLER_HELPER:'/helper',DOPPEL_PRIMARY_APP:'/primary',DOPPEL_PRIMARY_BUNDLE_ID:'primary'}};
  let require=name=>{check(name==='node:child_process','module');return {spawn:(path,args,opts)=>{
    check(path==='/helper' && args.join('|')==='set|codex|/primary|primary','restore destination');
    check(opts.detached && opts.stdio==='ignore','spawn options');spawned.push(args);return {unref:()=>{}};
  }}};
''' + patched + r'''
  T();
  if (!enabled) {check(listener===null && spawned.length===0,'disabled registration');return;}
  check(spawned.length===1 && callbacks[0]==='oauth','startup OAuth restoration');
  check(typeof handoff==='function','browser-handoff registration preserved');
  let prevented=0, event={preventDefault:()=>prevented++};
  listener(event,'oauth');
  check(spawned.length===2 && prevented===1,'live OAuth restoration');
  listener(event,'thread');listener(event,'https://example.test');listener(event,'unknown');
  check(spawned.length===2 && prevented===3 && http.length===1,'ordinary URLs unchanged');
  delete process.env.DOPPEL_URL_HANDLER_HELPER;
  listener(event,'oauth');check(spawned.length===2 && prevented===4,'missing helper safely ignored');
  process.env.DOPPEL_URL_HANDLER_HELPER='/helper';require=()=>{throw Error('spawn failed');};
  listener(event,'oauth');check(prevented===5,'spawn failure preserves callback handling');
  let count=callbacks.length;
  listener(event,'wake');
  check(queued[queued.length-1]==='wakeQueuedThread' && spawned.length===2 && prevented===6,'wake route still queued');
  check(callbacks.length===count+WAKE_CALLBACK_COUNT,'wake callback guard preserved');
}
exercise(false);exercise(true);'PASS';
'''
        javascript = javascript.replace('WAKE_CALLBACK_COUNT', str(int(wake_callback)))
        result = run_javascript(javascript)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_different_listener_target_rejected(self):
        changed = CURRENT.replace(b'n(t,e)}),', b'other(t,e)}),')
        self.assertIsNone(patcher.DRAINED_OPEN_URL_HANDLER.search(changed))

    def test_guard_on_different_route_rejected(self):
        changed = CURRENT.replace(b'n.kind!==', b'other.kind!==')
        self.assertIsNone(patcher.DRAINED_OPEN_URL_HANDLER.search(changed))


class OAuthClaimTests(unittest.TestCase):
    samples = (
        b'"app-connect-oauth-callback-url":async()=>({callbackUrl:`${r.u(l.app.isPackaged)}://connector/oauth_callback`})',
        b'"app-connect-oauth-callback-url":async()=>({callbackUrl:`${r.K(l.app.isPackaged)}://connector/oauth_callback`})',
        b'async getCallbackUrl(){return`${_.M(O.app.isPackaged)}://connector/oauth_callback`}',
        b'async getCallbackUrl(){return`${$a.$b($c.app.isPackaged)}://connector/oauth_callback`}',
    )

    def test_claims_protocol_and_preserves_return_type(self):
        for sample in self.samples:
            with self.subTest(sample=sample):
                match = patcher.OAUTH_CALLBACK_HANDLER.fullmatch(sample)
                self.assertIsNotNone(match)
                legacy = match.group('legacy') is not None
                patched = patcher.patched_oauth_handler(match).decode()
                handler = ('({' + patched + '})["app-connect-oauth-callback-url"]' if legacy
                           else 'new (class {' + patched + '})().getCallbackUrl')
                javascript = r'''
var doppelTestResult = 'pending';
(async()=>{
  function check(value,message){if(!value)throw Error(message);}
  let claims=[],checks=[],claim=true,owned=false;
  const app={
    setAsDefaultProtocolClient:scheme=>{claims.push(scheme);return claim;},
    isDefaultProtocolClient:scheme=>{checks.push(scheme);return owned;}
  };
  const l={app},O={app},$c={app};
  const handler=HANDLER;
  function checkResult(result){
    check(LEGACY ? typeof result==='object' : typeof result==='string','return type');
    check((LEGACY ? result.callbackUrl : result)==='codex://connector/oauth_callback','registered callback URL');
  }
  checkResult(await handler());
  check(claims.join()==='codex' && checks.length===0,'claim before returning callback');
  claim=false;owned=true;
  checkResult(await handler());
  check(claims.length===2 && checks.join()==='codex','existing ownership accepted');
  owned=false;
  let error=null;
  try{await handler();}catch(e){error=e;}
  check(error?.message==='Doppel could not claim codex:// OAuth callback','failed ownership rejects OAuth');
  check(claims.length===3 && checks.length===2,'ownership checked on every request');
  doppelTestResult='PASS';
})().catch(error=>{doppelTestResult=String(error.stack||error);});
'''
                javascript = javascript.replace('HANDLER', handler).replace('LEGACY', str(legacy).lower())
                result = run_javascript(javascript)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_other_methods_and_callback_paths_rejected(self):
        sample = self.samples[2]
        for changed in (sample.replace(b'getCallbackUrl', b'otherMethod'),
                        sample.replace(b'connector/oauth_callback', b'other/callback'),
                        sample.replace(b'app.isPackaged', b'app.otherProperty')):
            with self.subTest(sample=changed):
                self.assertIsNone(patcher.OAUTH_CALLBACK_HANDLER.search(changed))


if __name__ == '__main__':
    unittest.main()
