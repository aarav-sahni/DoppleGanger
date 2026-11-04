#!/usr/bin/python3
"""Check the stable bootstrap and Electron routing adapter, without real OAuth."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('patcher', Path(__file__).resolve().parents[1] / 'engine/patch-deep-link.py')
patcher = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = patcher
spec.loader.exec_module(patcher)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.path = Path(self.scratch.name) / 'app.asar'

    def make_archive(self, main='entry.js', kind=None, source=b'module.exports = 42;', extra=None):
        package = {'name': 'vendor-fixture', 'main': main}
        if kind:
            package['type'] = kind
        data = {'package.json': json.dumps(package).encode(), main: source,
                'arbitrary-vendor-chunk.js': b'class CompletelyDifferentBundler {}',
                'empty.js': b'', **(extra or {})}
        header = {'files': {}}
        payload = b''
        for name, content in data.items():
            entry = {'offset': str(len(payload)), 'size': len(content),
                     'integrity': {'algorithm': 'SHA256', 'blockSize': 4096}}
            patcher.refresh_member_integrity(entry, content)
            header['files'][name] = entry
            payload += content
        encoded, _ = patcher.encode_header(header)
        self.path.write_bytes(encoded + payload)
        return data

    def test_arbitrary_vendor_sources_unchanged_and_patch_idempotent(self):
        for source in (b'function oldMinifier(){return "codex"}',
                       b'(()=>{class RspackModule{#field=123}})();',
                       b'/* No protocol or OAuth code whatsoever */'):
            with self.subTest(source=source):
                before = self.make_archive(source=source)
                header_hash = patcher.patch(self.path)
                archive = patcher.read_archive(self.path)
                after = {member.path: patcher.read_member(archive, member) for member in patcher.members(archive)}
                for name, contents in before.items():
                    if name != 'package.json':
                        self.assertEqual(after[name], contents)
                self.assertEqual(len(after), len(before) + 2)
                unchanged = self.path.read_bytes()
                self.assertEqual(patcher.patch(self.path), header_hash)
                self.assertEqual(self.path.read_bytes(), unchanged)
                self.assertEqual(patcher.verify(self.path), header_hash)

    def test_cjs_and_esm_entry_points(self):
        for main, kind, esm in [('entry.js', None, False), ('entry.js', 'module', True),
                                ('entry.mjs', None, True), ('entry.cjs', 'module', False)]:
            with self.subTest(main=main, kind=kind):
                self.make_archive(main=main, kind=kind)
                patcher.patch(self.path)
                archive = patcher.read_archive(self.path)
                _, package, files = patcher.package_member(archive)
                self.assertEqual(package['doppelAdapter']['esm'], esm)
                self.assertEqual(patcher.read_member(archive, files[package['main']]),
                                 patcher.bootstrap_source(main, esm))

    def test_rejects_unsafe_missing_and_conflicting_entries_without_writing(self):
        for main in ('../entry.js', '/entry.js', 'bad\\entry.js'):
            with self.subTest(main=main):
                self.make_archive(main=main)
                before = self.path.read_bytes()
                with self.assertRaises(patcher.PatchError):
                    patcher.patch(self.path)
                self.assertEqual(self.path.read_bytes(), before)
        self.make_archive(extra={patcher.RUNTIME_PATH: b'collision'})
        before = self.path.read_bytes()
        with self.assertRaises(patcher.PatchError):
            patcher.patch(self.path)
        self.assertEqual(self.path.read_bytes(), before)

    def test_modified_adapter_and_vendor_entry_rejected(self):
        for target in ('entry.js', patcher.BOOTSTRAP_PATH, patcher.RUNTIME_PATH):
            with self.subTest(target=target):
                self.make_archive()
                patcher.patch(self.path)
                archive = patcher.read_archive(self.path)
                patcher.rewrite_members(archive, {target: b'changed'})
                with self.assertRaises(patcher.PatchError):
                    patcher.verify(self.path)

    def test_unmodified_vendor_is_not_accepted_as_adapted(self):
        self.make_archive()
        with self.assertRaises(patcher.PatchError):
            patcher.verify(self.path)


class RuntimeTests(unittest.TestCase):
    def test_electron_contract(self):
        node = shutil.which('node')
        bundled = Path('/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node')
        if not node and bundled.is_file():
            node = str(bundled)
        self.assertIsNotNone(node, 'Node is required (the vendor app includes it)')
        script = r'''
const assert = require('node:assert/strict');
const vm = require('node:vm');
const {EventEmitter} = require('node:events');
const source = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
function boot(options={}) {
  const calls=[],timers=[];
  const app=new EventEmitter();
  for(const method of ['setAsDefaultProtocolClient','isDefaultProtocolClient','removeAsDefaultProtocolClient']) {
    app[method]=function(...args) {
      assert.equal(this,app);calls.push([method,...args]);
      return method==='isDefaultProtocolClient' ? !!options.owned : options.claim!==false;
    };
  }
  const env={DOPPEL_URL_SCHEME:'codex-personal',DOPPEL_URL_HANDLER_HELPER:'/helper',
             DOPPEL_PRIMARY_APP:'/Applications/ChatGPT.app',DOPPEL_PRIMARY_BUNDLE_ID:'com.openai.codex',...options.env};
  const proc={env,argv:options.argv||['app','ordinary']};
  const shell={openExternal:async function(...args){assert.equal(this,shell);calls.push(['open',...args]);
    if(options.openFails)throw Error('browser failed');return 'opened';}};
  const context={module:{exports:{}},process:proc,URL,setImmediate:fn=>timers.push(fn),require:name=>{
    assert.equal(name,'node:child_process');return {spawn:(path,args,opts)=>{
      calls.push(['restore',path,args,opts]);if(options.spawnFails)throw Error('helper failed');
      return {unref:()=>calls.push(['unref'])};}};}};
  vm.runInNewContext(source,context);
  context.module.exports({app,shell});
  return {app,shell,proc,calls,timers};
}
(async()=>{
  const regular=boot();
  assert.equal(regular.calls.length,0,'normal startup never claims the shared callback');
  assert.equal(regular.app.setAsDefaultProtocolClient('codex','exe',['arg']),true);
  assert.equal(regular.calls[0][1],'codex-personal');
  assert.deepEqual(regular.calls[0].slice(2),['exe',['arg']]);
  regular.app.isDefaultProtocolClient('CODEX');regular.app.removeAsDefaultProtocolClient('codex-dev');
  assert.equal(regular.calls[1][1],'codex-personal');assert.equal(regular.calls[2][1],'codex-personal');
  regular.app.setAsDefaultProtocolClient('another-scheme');assert.equal(regular.calls[3][1],'another-scheme');
  const opts={activate:false};
  assert.equal(await regular.shell.openExternal('https://example.test/docs/oauth-guide',opts),'opened');
  assert.deepEqual(regular.calls.at(-1),['open','https://example.test/docs/oauth-guide',opts]);
  regular.app.emit('will-quit');assert(!regular.calls.some(c=>c[0]==='restore'));

  for(const url of ['https://example.test/start?redirect_uri='+encodeURIComponent('codex://connector/oauth_callback'),
                    'https://example.test/start?target='+encodeURIComponent(encodeURIComponent('codex://connector/oauth_callback')),
                    'https://accounts.example.test/o/oauth2/v2/auth',
                    'https://example.test/authorize',
                    'https://example.test/login?client_id=test&response_type=code']) {
    const oauth=boot();
    await oauth.shell.openExternal(url,opts);
    assert.equal(oauth.calls[0][0],'setAsDefaultProtocolClient');assert.equal(oauth.calls[0][1],'codex');
    assert.deepEqual(oauth.calls[1],['open',url,opts]);
    let delivered;const event={preventDefault:()=>{throw Error('adapter consumed the event');}};
    oauth.app.on('open-url',(e,value)=>{assert.equal(e,event);delivered=value;assert(!oauth.calls.some(c=>c[0]==='restore'));});
    assert.equal(oauth.app.emit('open-url',event,'codex://connector/oauth_callback?code=test'),true);
    assert.equal(delivered,'codex://connector/oauth_callback?code=test');
    const restore=oauth.calls.find(c=>c[0]==='restore');
    assert.equal(restore[1],'/helper');assert.equal(restore[2].join('|'),'set|codex|/Applications/ChatGPT.app|com.openai.codex');
    assert(restore[3].detached&&restore[3].stdio==='ignore');
  }
  const blocked=boot({claim:false});
  await assert.rejects(()=>blocked.shell.openExternal('https://example.test/oauth'),/could not claim/);
  assert(!blocked.calls.some(c=>c[0]==='open'));
  const alreadyOwned=boot({claim:false,owned:true});
  await alreadyOwned.shell.openExternal('https://example.test/oauth');assert.equal(alreadyOwned.calls[1][0],'isDefaultProtocolClient');
  const failedBrowser=boot({openFails:true});
  await assert.rejects(()=>failedBrowser.shell.openExternal('https://example.test/oauth'),/browser failed/);
  assert(failedBrowser.calls.some(c=>c[0]==='restore'));
  const quit=boot();await quit.shell.openExternal('https://example.test/oauth');quit.app.emit('will-quit');
  assert(quit.calls.some(c=>c[0]==='restore'));

  const intake=boot({argv:['app','codex-personal://thread/abc?foo=bar','not a URL']});
  assert.equal(intake.proc.argv[1],'codex://thread/abc?foo=bar');assert.equal(intake.proc.argv[2],'not a URL');
  let live;intake.app.on('open-url',(_,url)=>{live=url;});
  intake.app.emit('open-url',{},'codex-personal://thread/xyz');assert.equal(live,'codex://thread/xyz');
  intake.app.emit('open-url',{},'https://example.test');assert.equal(live,'https://example.test');
  assert(!intake.calls.some(c=>c[0]==='restore'));
  let second;intake.app.on('second-instance',(_,argv)=>{second=argv;});
  intake.app.emit('second-instance',{},['app','codex-personal://thread/xyz']);assert.equal(second[1],'codex://thread/xyz');
  const startup=boot({argv:['app','codex-personal://connector/oauth_callback?code=test']});
  assert.equal(startup.proc.argv[1],'codex://connector/oauth_callback?code=test');
  assert.equal(startup.timers.length,1);startup.timers[0]();assert(startup.calls.some(c=>c[0]==='restore'));
  for(const extra of [{spawnFails:true},{env:{DOPPEL_URL_HANDLER_HELPER:undefined}}]) {
    const safe=boot(extra);let got=false;safe.app.on('open-url',()=>{got=true;});
    safe.app.emit('open-url',{},'codex://connector/oauth_callback');assert(got);
  }
  const throwing=boot();throwing.app.on('open-url',()=>{throw Error('vendor error');});
  assert.throws(()=>throwing.app.emit('open-url',{},'codex://connector/oauth_callback'),/vendor error/);
  assert(throwing.calls.some(c=>c[0]==='restore'));
  for(const scheme of ['', 'codex','CODEX','codex-dev','bad scheme']) {
    assert.throws(()=>boot({env:{DOPPEL_URL_SCHEME:scheme}}),/private URL scheme/);
  }
  console.log('Electron routing, OAuth ownership, event delivery, startup URLs, and failure handling passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
        result = subprocess.run([node, '-e', script], input=json.dumps(patcher.RUNTIME_SOURCE.decode()),
                                text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
