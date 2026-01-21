'use strict';

// ==================== Constants ====================
var RTLD_NOW = 2;
var RTLD_GLOBAL = 8;
var DT_UNKNOWN = 0;
var DT_DIR = 4;

// ==================== Cached Function Pointers ====================
var cachedFunctions = {
  dlopen: null,
  opendir: null,
  readdir: null,
  closedir: null,
  access: null,
  mkdir: null,
  unlink: null,
  getenv: null
};

// ==================== Utility Functions ====================

function getDirentOffsets() {
  if (Process.pointerSize === 8) {
    return { namlen: 18, dtype: 20, name: 21 };
  }
  return { namlen: 10, dtype: 12, name: 13 };
}

function allocUtf8String(value) {
  var buf = Memory.alloc(value.length + 1);
  buf.writeUtf8String(value);
  return buf;
}

function findExport(name) {
  if (typeof Module === 'undefined') {
    return null;
  }
  if (typeof Module.findExportByName === 'function') {
    return Module.findExportByName(null, name);
  }
  if (typeof Module.getExportByName === 'function') {
    try {
      return Module.getExportByName(null, name);
    } catch (e) {
      return null;
    }
  }
  if (typeof Module.getGlobalExportByName === 'function') {
    try {
      return Module.getGlobalExportByName(name);
    } catch (e) {
      return null;
    }
  }
  return null;
}

function enumerateModules() {
  if (typeof Process.enumerateModulesSync === 'function') {
    return Process.enumerateModulesSync();
  }
  if (typeof Process.enumerateModules === 'function') {
    return Process.enumerateModules();
  }
  return [];
}

// ==================== Lazy Function Getters ====================

function getCachedFunction(name, retType, argTypes) {
  if (cachedFunctions[name] === null) {
    var ptr = findExport(name);
    if (ptr) {
      cachedFunctions[name] = new NativeFunction(ptr, retType, argTypes);
    }
  }
  return cachedFunctions[name];
}

function getDlopen() {
  return getCachedFunction('dlopen', 'pointer', ['pointer', 'int']);
}

function getOpendir() {
  return getCachedFunction('opendir', 'pointer', ['pointer']);
}

function getReaddir() {
  return getCachedFunction('readdir', 'pointer', ['pointer']);
}

function getClosedir() {
  return getCachedFunction('closedir', 'int', ['pointer']);
}

function getAccess() {
  return getCachedFunction('access', 'int', ['pointer', 'int']);
}

function getMkdir() {
  return getCachedFunction('mkdir', 'int', ['pointer', 'int']);
}

function getUnlink() {
  return getCachedFunction('unlink', 'int', ['pointer']);
}

function getGetenv() {
  return getCachedFunction('getenv', 'pointer', ['pointer']);
}

// ==================== Path Utilities ====================

function getEnvVar(name) {
  var getenv = getGetenv();
  if (!getenv) {
    return null;
  }
  var valuePtr = getenv(allocUtf8String(name));
  if (valuePtr.isNull()) {
    return null;
  }
  return valuePtr.readUtf8String();
}

function pathExists(path) {
  var access = getAccess();
  if (!access) {
    return true;
  }
  return access(allocUtf8String(path), 0) === 0;
}

function ensureDirPosix(path) {
  var mkdir = getMkdir();
  if (!mkdir) {
    throw new Error('mkdir is unavailable.');
  }
  var parts = path.split('/');
  var current = '';
  for (var i = 0; i < parts.length; i++) {
    var part = parts[i];
    if (!part) {
      current = '/';
      continue;
    }
    if (current === '/' || current === '') {
      current = '/' + part;
    } else {
      current = current + '/' + part;
    }
    mkdir(allocUtf8String(current), 493);
  }
}

function listDirPosix(path) {
  var opendir = getOpendir();
  var readdir = getReaddir();
  var closedir = getClosedir();
  if (!opendir || !readdir || !closedir) {
    throw new Error('POSIX directory APIs are unavailable.');
  }

  var dirp = opendir(allocUtf8String(path));
  if (dirp.isNull()) {
    return [];
  }

  var entries = [];
  var offsets = getDirentOffsets();
  while (true) {
    var ent = readdir(dirp);
    if (ent.isNull()) {
      break;
    }
    var nameLen = ent.add(offsets.namlen).readU16();
    var name = ent.add(offsets.name).readUtf8String(nameLen);
    if (!name || name === '.' || name === '..') {
      continue;
    }
    var dtype = ent.add(offsets.dtype).readU8();
    entries.push({ name: name, dtype: dtype });
  }

  closedir(dirp);
  return entries;
}

// ==================== Objective-C Runtime ====================

function tryLoadObjC() {
  if (typeof ObjC !== 'undefined' && ObjC.available) {
    return true;
  }

  if (typeof Module !== 'undefined') {
    if (typeof Module.load === 'function') {
      try {
        Module.load('/usr/lib/libobjc.A.dylib');
      } catch (e) {
        // Ignore and retry later.
      }
    }

    var dlopen = getDlopen();
    if (dlopen) {
      try {
        dlopen(allocUtf8String('/usr/lib/libobjc.A.dylib'), RTLD_NOW | RTLD_GLOBAL);
      } catch (e) {
        // Ignore and retry later.
      }
    }

    if (typeof Module.ensureInitialized === 'function') {
      try {
        Module.ensureInitialized('Foundation');
      } catch (e) {
        // Ignore and retry later.
      }
    }
  }

  return (typeof ObjC !== 'undefined' && ObjC.available);
}

function ensureObjCAvailable() {
  if (!tryLoadObjC()) {
    throw new Error('Objective-C runtime is not available yet.');
  }
}

// ==================== Bundle Info ====================

function getMainAppModule() {
  var main = Process.mainModule;
  if (main && main.path.indexOf('.app/') !== -1) {
    return main;
  }

  var modules = enumerateModules();
  var appModules = modules.filter(function (m) {
    return m.path.indexOf('.app/') !== -1;
  });

  if (appModules.length === 0) {
    return main || (modules.length > 0 ? modules[0] : null);
  }

  for (var i = 0; i < appModules.length; i++) {
    var mod = appModules[i];
    if (mod.path.endsWith('/' + mod.name)) {
      return mod;
    }
  }

  return appModules[0];
}

function getBundleInfoFallback() {
  var mod = getMainAppModule();
  if (!mod) {
    return {
      appName: null,
      bundlePath: null,
      executablePath: null,
      executableName: null,
      bundleId: null
    };
  }

  var executablePath = mod.path;
  var executableName = mod.name;
  var idx = executablePath.indexOf('.app/');
  var bundlePath = idx >= 0 ? executablePath.substring(0, idx + 4) : null;
  var appName = null;
  if (bundlePath) {
    var parts = bundlePath.split('/');
    var last = parts[parts.length - 1];
    if (last && last.endsWith('.app')) {
      appName = last.substring(0, last.length - 4);
    }
  }

  return {
    appName: appName,
    bundlePath: bundlePath,
    executablePath: executablePath,
    executableName: executableName,
    bundleId: null
  };
}

function getBundleInfo() {
  var info = getBundleInfoFallback();
  if (!tryLoadObjC()) {
    return info;
  }

  var bundle = ObjC.classes.NSBundle.mainBundle();
  var infoDict = bundle.infoDictionary();
  var displayName = infoDict.objectForKey_('CFBundleDisplayName');
  var bundleName = infoDict.objectForKey_('CFBundleName');
  var appName = displayName ? displayName.toString() : (bundleName ? bundleName.toString() : null);
  var bundlePath = bundle.bundlePath().toString();
  var executablePath = bundle.executablePath().toString();
  var executableName = executablePath.split('/').pop();
  var bundleId = bundle.bundleIdentifier().toString();
  return {
    appName: appName || info.appName,
    bundlePath: bundlePath || info.bundlePath,
    executablePath: executablePath || info.executablePath,
    executableName: executableName || info.executableName,
    bundleId: bundleId || info.bundleId
  };
}

function getSandboxPath() {
  if (tryLoadObjC()) {
    try {
      var env = ObjC.classes.NSProcessInfo.processInfo().environment();
      var home = env.objectForKey_('HOME');
      if (home) {
        return home.toString();
      }
    } catch (e) {
      // Ignore and fall back.
    }
  }

  return getEnvVar('HOME');
}

// ==================== Mach-O Parsing ====================

function readU64Number(ptrValue) {
  return ptrValue.readU64().toNumber();
}

function readSegmentName(ptrValue) {
  var raw = ptrValue.readByteArray(16);
  var bytes = new Uint8Array(raw);
  var name = '';
  for (var i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0) {
      break;
    }
    name += String.fromCharCode(bytes[i]);
  }
  return name;
}

function parseMachO(base) {
  var MH_MAGIC_64 = 0xfeedfacf;
  var MH_CIGAM_64 = 0xcffaedfe;
  var MH_MAGIC = 0xfeedface;
  var MH_CIGAM = 0xcefaedfe;
  var LC_SEGMENT = 0x1;
  var LC_SEGMENT_64 = 0x19;
  var LC_ENCRYPTION_INFO = 0x21;
  var LC_ENCRYPTION_INFO_64 = 0x2c;

  var magic = base.readU32();
  var is64 = (magic === MH_MAGIC_64 || magic === MH_CIGAM_64);
  if (!(is64 || magic === MH_MAGIC || magic === MH_CIGAM)) {
    throw new Error('Unsupported Mach-O magic: ' + magic);
  }

  var headerSize = is64 ? 32 : 28;
  var ncmds = base.add(16).readU32();
  var cmdOffset = headerSize;
  var segments = [];
  var cryptidOffset = null;
  var textVmaddr = null;
  var fallbackVmaddr = null;

  for (var i = 0; i < ncmds; i++) {
    var cmd = base.add(cmdOffset).readU32();
    var cmdsize = base.add(cmdOffset + 4).readU32();

    if (cmd === LC_SEGMENT || cmd === LC_SEGMENT_64) {
      var segname = readSegmentName(base.add(cmdOffset + 8));
      var vmaddr = is64 ? readU64Number(base.add(cmdOffset + 24)) : base.add(cmdOffset + 24).readU32();
      var vmsize = is64 ? readU64Number(base.add(cmdOffset + 32)) : base.add(cmdOffset + 28).readU32();
      var fileoff = is64 ? readU64Number(base.add(cmdOffset + 40)) : base.add(cmdOffset + 32).readU32();
      var filesize = is64 ? readU64Number(base.add(cmdOffset + 48)) : base.add(cmdOffset + 36).readU32();

      if (segname === '__TEXT') {
        textVmaddr = vmaddr;
      }
      if (fallbackVmaddr === null && fileoff === 0 && filesize > 0) {
        fallbackVmaddr = vmaddr;
      }

      segments.push({
        segname: segname,
        vmaddr: vmaddr,
        vmsize: vmsize,
        fileoff: fileoff,
        filesize: filesize
      });
    }

    if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
      cryptidOffset = cmdOffset + 16;
    }

    cmdOffset += cmdsize;
  }

  return {
    is64: is64,
    segments: segments,
    cryptidOffset: cryptidOffset,
    textVmaddr: textVmaddr,
    fallbackVmaddr: fallbackVmaddr
  };
}

// ==================== File Operations ====================

function ensureDir(path) {
  if (tryLoadObjC()) {
    var fm = ObjC.classes.NSFileManager.defaultManager();
    if (fm.fileExistsAtPath_(path)) {
      return;
    }
    fm.createDirectoryAtPath_withIntermediateDirectories_attributes_error_(
      path,
      true,
      NULL,
      NULL
    );
    return;
  }
  ensureDirPosix(path);
}

function dumpExecutable(outPath) {
  var info = getBundleInfo();
  var module = null;
  if (info.executableName) {
    try {
      module = Process.getModuleByName(info.executableName);
    } catch (e) {
      module = null;
    }
  }
  if (!module) {
    module = getMainAppModule();
  }
  if (!module) {
    throw new Error('Unable to locate main module.');
  }
  var base = module.base;
  var parsed = parseMachO(base);
  var baseVmaddr = parsed.textVmaddr !== null ? parsed.textVmaddr : parsed.fallbackVmaddr;
  if (baseVmaddr === null) {
    throw new Error('Unable to find a base segment for slide calculation.');
  }

  var dir = outPath.split('/').slice(0, -1).join('/');
  if (dir.length > 0) {
    ensureDir(dir);
  }

  var out = new File(outPath, 'wb');

  parsed.segments.forEach(function (seg) {
    if (seg.filesize === 0) {
      return;
    }
    var offset = seg.vmaddr - baseVmaddr;
    var addr = base.add(offset);
    var readSize = seg.filesize;
    if (seg.vmsize && seg.vmsize < readSize) {
      readSize = seg.vmsize;
    }

    var data = addr.readByteArray(readSize);
    out.seek(seg.fileoff, File.SEEK_SET);
    out.write(data);

    if (readSize < seg.filesize) {
      out.seek(seg.fileoff + seg.filesize - 1, File.SEEK_SET);
      out.write(new Uint8Array([0]).buffer);
    }
  });

  if (parsed.cryptidOffset !== null) {
    out.seek(parsed.cryptidOffset, File.SEEK_SET);
    out.write(new Uint8Array([0, 0, 0, 0]).buffer);
  }

  out.flush();
  out.close();

  return {
    outPath: outPath,
    bundlePath: info.bundlePath,
    executableName: info.executableName || module.name
  };
}

function statPath(path) {
  if (tryLoadObjC()) {
    var fm = ObjC.classes.NSFileManager.defaultManager();
    var isDirPtr = Memory.alloc(1);
    isDirPtr.writeU8(0);
    var exists = fm.fileExistsAtPath_isDirectory_(path, isDirPtr);
    if (!exists) {
      return { exists: false };
    }
    var isDir = isDirPtr.readU8() !== 0;
    var size = 0;
    if (!isDir) {
      var file = new File(path, 'rb');
      file.seek(0, File.SEEK_END);
      size = file.tell();
      file.close();
    }
    return { exists: true, isDir: isDir, size: size };
  }

  if (!pathExists(path)) {
    return { exists: false };
  }

  var opendir = getOpendir();
  var closedir = getClosedir();
  if (opendir && closedir) {
    var dirp = opendir(allocUtf8String(path));
    if (!dirp.isNull()) {
      closedir(dirp);
      return { exists: true, isDir: true, size: 0 };
    }
  }

  var size = 0;
  try {
    var file = new File(path, 'rb');
    file.seek(0, File.SEEK_END);
    size = file.tell();
    file.close();
  } catch (e) {
    size = 0;
  }
  return { exists: true, isDir: false, size: size };
}

/**
 * Batch stat multiple paths at once.
 * Returns an object mapping each path to its stat result.
 */
function statPaths(paths) {
  var results = {};
  for (var i = 0; i < paths.length; i++) {
    results[paths[i]] = statPath(paths[i]);
  }
  return results;
}

function listFiles(rootPath) {
  if (tryLoadObjC()) {
    var fm = ObjC.classes.NSFileManager.defaultManager();
    var enumerator = fm.enumeratorAtPath_(rootPath);
    var files = [];
    var dirs = [];
    var item;
    while ((item = enumerator.nextObject()) !== null) {
      var rel = item.toString();
      var full = rootPath + '/' + rel;
      var isDirPtr = Memory.alloc(1);
      isDirPtr.writeU8(0);
      fm.fileExistsAtPath_isDirectory_(full, isDirPtr);
      var isDir = isDirPtr.readU8() !== 0;
      if (isDir) {
        dirs.push(rel);
      } else {
        files.push(rel);
      }
    }
    return { files: files, dirs: dirs };
  }

  var files = [];
  var dirs = [];

  function walk(currentPath, relBase) {
    var entries = listDirPosix(currentPath);
    for (var i = 0; i < entries.length; i++) {
      var entry = entries[i];
      var name = entry.name;
      var rel = relBase ? (relBase + '/' + name) : name;
      var full = currentPath + '/' + name;
      var isDir = entry.dtype === DT_DIR;
      if (entry.dtype === DT_UNKNOWN) {
        var opendir = getOpendir();
        var closedir = getClosedir();
        if (opendir && closedir) {
          var dirp = opendir(allocUtf8String(full));
          if (!dirp.isNull()) {
            closedir(dirp);
            isDir = true;
          }
        }
      }
      if (isDir) {
        dirs.push(rel);
        walk(full, rel);
      } else {
        files.push(rel);
      }
    }
  }

  walk(rootPath, '');
  return { files: files, dirs: dirs };
}

function readFile(path, offset, size) {
  var file = new File(path, 'rb');
  file.seek(offset, File.SEEK_SET);
  var data = file.readBytes(size);
  file.close();
  return data;
}

function removePath(path) {
  if (tryLoadObjC()) {
    var fm = ObjC.classes.NSFileManager.defaultManager();
    fm.removeItemAtPath_error_(path, NULL);
    return true;
  }
  var unlink = getUnlink();
  if (!unlink) {
    return false;
  }
  return unlink(allocUtf8String(path)) === 0;
}

// ==================== RPC Exports ====================

rpc.exports = {
  getbundleinfo: getBundleInfo,
  getsandboxpath: getSandboxPath,
  dumpexecutable: dumpExecutable,
  listfiles: listFiles,
  statpath: statPath,
  statpaths: statPaths,
  readfile: readFile,
  removepath: removePath
};
