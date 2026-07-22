// Dump Reeden's Hive key candidate from Flutter AOT runtime.
// Run with:
//   frida -U -f app.reeden -l scripts/dump_reeden_hive_key.js --no-pause

'use strict';

const LIB = 'libapp.so';
const OFFSETS = {
  buildKeyHelper: 0x224e84c,
  buildKeyEntry: 0x224e78c,
  openSettingsTask: 0x224e068,
};

let installed = false;

function heapBaseFromContext(ctx) {
  const high = BigInt(ctx.x28.toString());
  return ptr('0x' + (high << 32n).toString(16));
}

function decomp(heapBase, raw32) {
  return heapBase.add(raw32 >>> 0);
}

function smi(raw32) {
  return (raw32 >> 1) >>> 0;
}

function byteHex(xs) {
  return xs.map(v => ('0' + (v & 0xff).toString(16)).slice(-2)).join('');
}

function readGrowableListBytes(obj, heapBase) {
  const lenRaw = obj.add(0x0b).readU32();
  const len = smi(lenRaw);
  const dataRaw = obj.add(0x0f).readU32();
  const backing = decomp(heapBase, dataRaw);
  const backingLen = smi(backing.add(0x0b).readU32());
  const n = Math.min(len, backingLen, 128);
  const out = [];
  for (let i = 0; i < n; i++) {
    const elemRaw = backing.add(0x0f + i * 4).readU32();
    if ((elemRaw & 1) !== 0) return null;
    out.push(smi(elemRaw) & 0xff);
  }
  return { kind: 'GrowableList', len, backing, backingLen, bytes: out };
}

function readFixedListBytes(obj) {
  const lenRaw = obj.add(0x0b).readU32();
  const len = smi(lenRaw);
  if (len <= 0 || len > 128) return null;
  const out = [];
  for (let i = 0; i < len; i++) {
    const elemRaw = obj.add(0x0f + i * 4).readU32();
    if ((elemRaw & 1) !== 0) return null;
    out.push(smi(elemRaw) & 0xff);
  }
  return { kind: 'FixedList', len, bytes: out };
}

function dumpDartList(label, obj, heapBase) {
  try {
    console.log(`[+] ${label} retval=${obj} heapBase=${heapBase}`);
    console.log(hexdump(obj.sub(1), { length: 0x60, ansi: false }));

    const variants = [];
    const grow = readGrowableListBytes(obj, heapBase);
    if (grow) variants.push(grow);
    const fixed = readFixedListBytes(obj);
    if (fixed) variants.push(fixed);

    for (const v of variants) {
      console.log(`[+] ${label} ${v.kind} len=${v.len}` +
        (v.backing ? ` backing=${v.backing} backingLen=${v.backingLen}` : ''));
      console.log(`[+] ${label} bytes=${byteHex(v.bytes)}`);
    }
  } catch (e) {
    console.log(`[-] ${label} parse failed: ${e.stack || e}`);
  }
}

function installHooks() {
  if (installed) return;
  const lib = Process.findModuleByName(LIB);
  if (!lib) return;
  installed = true;
  console.log(`[+] ${LIB} base=${lib.base}`);

  for (const [name, off] of Object.entries(OFFSETS)) {
    const addr = lib.base.add(off);
    console.log(`[+] hook ${name} @ ${addr}`);
    Interceptor.attach(addr, {
      onEnter(args) {
        this.heapBase = heapBaseFromContext(this.context);
        console.log(`[>] enter ${name}`);
      },
      onLeave(retval) {
        console.log(`[<] leave ${name} retval=${retval}`);
        dumpDartList(name, retval, this.heapBase);
      },
    });
  }
}

const dlopen = Module.findGlobalExportByName('android_dlopen_ext') ||
  Module.findGlobalExportByName('dlopen');
if (dlopen) {
  Interceptor.attach(dlopen, {
    onEnter(args) {
      this.path = args[0].isNull() ? '' : args[0].readCString();
    },
    onLeave() {
      if (this.path.indexOf(LIB) !== -1) {
        console.log(`[+] loaded ${this.path}`);
        installHooks();
      }
    },
  });
}

const timer = setInterval(() => {
  installHooks();
  if (installed) clearInterval(timer);
}, 25);
