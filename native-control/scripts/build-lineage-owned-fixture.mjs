import fs from 'node:fs';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Builds the owned lineage qualification fixture (fixture addon + owned child)
// into native-control/build/owned-lineage-fixture/. This is a local test
// fixture only: the output is a private, unsigned, untrusted development
// artifact that is never a release input. Windows with a Visual Studio 2022+
// C++ toolchain is required; anything else fails closed.
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
if (process.platform !== 'win32' || process.arch !== 'x64') {
  console.error('build-lineage-owned-fixture: Windows x64 with MSVC is required');
  process.exit(1);
}
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const sources = {
  header: 'src/windows-lineage.h',
  addon: 'test-fixtures/windows-lineage-owned-addon.cc',
  child: 'test-fixtures/windows-lineage-owned-child.cc',
};
const pins = Object.fromEntries(Object.entries(sources).map(([key, relative]) => {
  const path = resolve(packageRoot, relative);
  return [key, { path: relative, bytes: fs.statSync(path).size, sha256: hash(fs.readFileSync(path)) }];
}));

const vcvars = process.env.GJC_LINEAGE_OWNED_VCVARS
  ?? 'C:/Program Files/Microsoft Visual Studio/18/Community/VC/Auxiliary/Build/vcvars64.bat';
if (!fs.existsSync(vcvars)) {
  console.error(`build-lineage-owned-fixture: vcvars64.bat not found at ${vcvars}; set GJC_LINEAGE_OWNED_VCVARS`);
  process.exit(1);
}
const headers = process.env.GJC_LINEAGE_OWNED_NODE_HEADERS
  ?? `${process.env.LOCALAPPDATA}/node-gyp/Cache/${process.version.slice(1)}/include/node`;
const nodeLibrary = process.env.GJC_LINEAGE_OWNED_NODE_LIB
  ?? `${process.env.LOCALAPPDATA}/node-gyp/Cache/${process.version.slice(1)}/x64/node.lib`;
for (const [name, path] of [['node headers', headers], ['node library', nodeLibrary]]) {
  if (!fs.existsSync(path)) {
    console.error(`build-lineage-owned-fixture: ${name} not found at ${path}; run node-gyp once or set the override`);
    process.exit(1);
  }
}

const output = resolve(packageRoot, 'build', 'owned-lineage-fixture');
fs.rmSync(output, { recursive: true, force: true });
fs.mkdirSync(output, { recursive: true });
const work = resolve(output, 'work');
fs.mkdirSync(work);
const cmd = [
  '@echo off',
  `call "${vcvars}"`,
  'if errorlevel 1 exit /b %errorlevel%',
  `cl /nologo /std:c++17 /EHsc /MD /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_WIN32_WINNT=0x0A00 /DNAPI_VERSION=8 /I"${headers}" /LD /Fo"${work}/owned-addon.obj" "${resolve(packageRoot, sources.addon)}" /link "${nodeLibrary}" advapi32.lib bcrypt.lib /OUT:"${resolve(output, 'owned-lineage.node')}" /IMPLIB:"${work}/owned-addon.lib" /PDB:"${work}/owned-addon.pdb"`,
  'if errorlevel 1 exit /b %errorlevel%',
  `cl /nologo /std:c++17 /EHsc /MD /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_WIN32_WINNT=0x0A00 /Fo"${work}/owned-child.obj" "${resolve(packageRoot, sources.child)}" /link advapi32.lib /OUT:"${resolve(output, 'owned-child.exe')}" /PDB:"${work}/owned-child.pdb"`,
  'exit /b %errorlevel%',
].join('\r\n') + '\r\n';
fs.writeFileSync(resolve(work, 'compile.cmd'), cmd);
const child = spawn(process.env.COMSPEC ?? 'C:/Windows/System32/cmd.exe', ['/d', '/c', resolve(work, 'compile.cmd')], {
  cwd: work,
  env: { TEMP: work, TMP: work, VSCMD_SKIP_SENDTELEMETRY: '1', VSCMD_SKIP_BANNER: '1', SystemRoot: process.env.SystemRoot, PATH: process.env.PATH, PATHEXT: process.env.PATHEXT, COMSPEC: process.env.COMSPEC },
  stdio: 'inherit',
});
const status = await new Promise(done => child.once('close', done));
assert.equal(status, 0, 'fixture compile failed');
fs.writeFileSync(resolve(output, 'build.json'), JSON.stringify({
  schema: 'gjc-lineage-owned-fixture-build/v1',
  sources: pins,
  outputs: ['owned-lineage.node', 'owned-child.exe'].map(name => {
    const path = resolve(output, name);
    return { name, bytes: fs.statSync(path).size, sha256: hash(fs.readFileSync(path)) };
  }),
}, null, 2) + '\n');
console.log(`owned lineage fixture built at ${output}`);
