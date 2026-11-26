# /// script
# requires-python = ">=3.9"
# dependencies = ["UnityPy==1.25.4", "pycryptodome==4.6.0", "lz4==4.4.5", "numpy==2.0.2"]
# ///
import argparse, gzip, hashlib, json, os, shutil, struct, subprocess, sys, urllib.request, warnings, zipfile
from pathlib import Path

import lz4.block
import numpy as np
import UnityPy
from UnityPy.helpers import ArchiveStorageManager

warnings.filterwarnings("ignore")

ArchiveStorageManager.UNITY3D_SIGNATURE = b"#$manjuuunity*!@"
UnityPy.config.FALLBACK_UNITY_VERSION = "2022.3.62f3"
UnityPy.set_assetbundle_decrypt_key("z4l23bh5#35h&321")

HERE = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve().parent
DEFAULT_GAME = Path(r"C:\YostarGames\AZUPRO_JP")
PROCS = ("azurpromiliajp.exe", "azupro_jp_gamelauncher.exe")
MMAP_MAGIC = b"\x01\x00\x00\x00\x10\x10\x00\x00"
POOL_PATH = b"Assets/ResourcesAssets/Config/VString/vstring.bytes"
MENU_PATH = b"Assets/ResourcesLang/jp/UI/StaticText/ast_staticTextKeyConfig.asset"
MENU_PREFIX = "ab220a0f5775655d2a8a0529e3fdefd87ea3cabd6197b4500d71bc5c1289a30d:"
CHANNEL = "https://raw.githubusercontent.com/Lani27/azur-promilia-english-patch/main/channel.json"
DATA_PREFIX = "https://github.com/Lani27/azur-promilia-english-patch/releases/download/"
H = 0x1018


def sha(b):
    return hashlib.sha256(b).hexdigest()


def sha_file(p):
    return sha(Path(p).read_bytes()) if os.path.exists(p) else None


def write(p, data):
    tmp = f"{p}.azp-tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)


def xor(data, K):
    a = np.frombuffer(data, np.uint8).copy()
    k = np.frombuffer(K, np.uint8).astype(np.int64)
    p = np.arange(H, len(a), dtype=np.int64)
    a[H:] ^= k[(k[(p >> 12) & 0xFF] + p) & 0xFFF].astype(np.uint8)
    return a.tobytes()


def recover_key(paths):
    pages = []
    for p in paths:
        mm = np.memmap(p, np.uint8, mode="r")
        n = len(mm) // 4096
        pages.append(mm[:n * 4096].reshape(n, 4096))
    cols = np.arange(4096, dtype=np.int64) * 256
    E = np.zeros((256, 4096), np.uint8)
    for m in range(256):
        c = np.zeros(4096 * 256, np.int64)
        for pg in pages:
            s = np.asarray(pg[(m or 256)::256])
            if len(s):
                c += np.bincount((s.astype(np.int64) + cols).ravel(), minlength=4096 * 256)
        E[m] = c.reshape(4096, 256).argmax(axis=1)
    best, K = -1, None
    for s in range(256):
        k = np.roll(E[0], s)
        if k[0] == s:
            score = sum(int((np.roll(k, -int(k[m])) == E[m]).sum()) for m in range(0, 256, 8))
            if score > best:
                best, K = score, k
    if best < 0.99 * 32 * 4096:
        sys.exit("could not recover the archive key")
    return K.tobytes()


class VString:
    def __init__(self, enc, K):
        d = self.d = xor(enc, K)
        X, a, b, bend, nb, nrec = struct.unpack_from("<6I", d, H)
        if (a, b) != (H, 0x1030) or bend != 0x1030 + 4 * nb:
            raise ValueError("not a VString pool")
        self.end = X + H
        size, selfp, self.idx, _, self.count = struct.unpack_from("<5I", d, self.end)
        if selfp != self.end or size + self.end != len(d) or self.count != nrec:
            raise ValueError("unexpected VString layout")

    def get(self, i):
        o = struct.unpack_from("<I", self.d, self.idx + 4 * i)[0]
        n = struct.unpack_from("<i", self.d, o)[0]
        return None if n < 0 else self.d[o + 4:o + 4 + n]

    def translated(self, tr):
        for i in range(self.count):
            s = self.get(i)
            en = tr.get(sha(s)) if s else None
            yield i, s, None if en is None else en.encode()

    def build(self, K, tr):
        d, tail = bytearray(self.d), bytearray()
        for i, _, en in self.translated(tr):
            if en is not None:
                struct.pack_into("<I", d, self.idx + 4 * i, len(d) + len(tail))
                tail += struct.pack("<i", len(en)) + en
        d += tail
        struct.pack_into("<I", d, self.end, len(d) - self.end)
        out = xor(bytes(d), K)
        new = VString(out, K)
        if any(new.get(i) != (en if en is not None else s) for i, s, en in self.translated(tr)):
            sys.exit("vstring readback failed; nothing was changed")
        return out


def is_pool(enc, K):
    try:
        return VString(enc, K).get(1) == POOL_PATH
    except Exception:
        return False


def manifest_bundle(d, path_id):
    p = 4 + 2 + struct.unpack_from("<H", d, 4)[0] + 11
    for _ in range(4):
        p += 2 + struct.unpack_from("<H", d, p)[0]
    na = struct.unpack_from("<i", d, p)[0]
    bundle = next((b for b, a in (struct.unpack_from("<2i", d, p + 4 + 24 * i) for i in range(na)) if a == path_id), None)
    if bundle is None:
        sys.exit("menu text asset not in manifest")
    p += 4 + 24 * na
    p += 8 + 4 * struct.unpack_from("<i", d, p)[0] + 56 * bundle
    return struct.unpack_from("<q", d, p)[0], struct.unpack_from("<q", d, p + 36)[0]


def menu_rows(raw):
    def rd(p):
        n = struct.unpack_from("<i", raw, p)[0]
        return raw[p + 4:p + 4 + n], (p + 4 + n + 3) & ~3

    def wr(s):
        o = struct.pack("<i", len(s)) + s
        return o + b"\0" * (-len(o) % 4)

    name, p = rd(28)
    lang, p = rd(p)
    n, p, rows = struct.unpack_from("<i", raw, p)[0], p + 4, []
    for _ in range(n):
        k, p = rd(p)
        t, p = rd(p)
        rows.append((k, t))
    head, tail = raw[:28] + wr(name) + wr(lang), raw[p:]
    return rows, lambda rows: head + struct.pack("<i", len(rows)) + b"".join(wr(k) + wr(t) for k, t in rows) + tail


def menu_object(bundle):
    env = UnityPy.load(bundle)
    return env, next(o for o in env.objects if o.class_id == 114)


def translate_menu(bundle, tr):
    env, mb = menu_object(bundle)
    raw = mb.get_raw_data()
    rows, build = menu_rows(raw)
    if build(rows) != raw:
        sys.exit("menu text layout changed")
    hit = 0
    for i, (k, t) in enumerate(rows):
        e = tr.get(k.decode())
        if e and sha(t) == e[0]:
            rows[i] = (k, e[1].encode())
            hit += 1
    new = build(rows)
    mb.set_raw_data(new)
    name, node = next(iter(env.file.files.items()))
    print(f"    menu: {hit:,}/{len(rows):,} rows replaced")
    return write_bundle(bundle, name, getattr(node, "flags", 4), node.save()), new


def encrypt_block(data, seq, index, sub):
    inv = [0] * 16
    for c, v in enumerate(index):
        inv[v & 0xF] = c
    d, pos, ctr = bytearray(data), 0, 0

    def enc():
        nonlocal pos, ctr
        p, i = d[pos], ctr
        k = sub[((i >> 2) & 3) + 4] + sub[i & 3] + sub[((i >> 4) & 3) + 8] + sub[(i % 256 >> 6) + 12]
        d[pos] = (inv[((p >> 4) + k) & 0xF] << 4) | inv[((p & 0xF) + k) & 0xF]
        pos, ctr = pos + 1, ctr + 1
        return p

    while pos < len(d):
        ctr = seq
        tok = enc()
        lit = tok >> 4
        if lit == 0xF:
            while (b := enc()) == 0xFF:
                lit += b
            lit += b
        pos += lit
        if pos < len(d):
            enc(), enc()
            if tok & 0xF == 0xF:
                while enc() == 0xFF:
                    pass
        seq += 1
    return bytes(d)


def write_bundle(orig, name, node_flags, data, bs=0x20000):
    dec = UnityPy.load(orig).file.decryptor
    p = orig.index(b"\0", orig.index(b"\0", 12) + 1) + 1
    head, flags, cn = orig[:p], struct.unpack_from(">I", orig, p + 16)[0], orig[p + 20:p + 90]
    lz = lambda b: lz4.block.compress(b, store_size=False, mode="high_compression")
    chunks = [data[o:o + bs] for o in range(0, len(data), bs)]
    blocks = [encrypt_block(lz(c), i, dec.index, dec.substitute) for i, c in enumerate(chunks)]
    info = b"\0" * 16 + struct.pack(">i", len(blocks))
    info += b"".join(struct.pack(">IIH", len(c), len(b), 0x103) for c, b in zip(chunks, blocks))
    info += struct.pack(">iqqI", 1, 0, len(data), node_flags) + name.encode() + b"\0"
    ci = lz(info)

    def build(total):
        o = head + struct.pack(">qIII", total, len(ci), len(info), flags) + cn
        o += b"\0" * (-len(o) % 16) + ci
        if flags & 0x200:
            o += b"\0" * (-len(o) % 16)
        return o + b"".join(blocks)

    return build(len(build(0)))


def has_container(bundle, path):
    for o in UnityPy.load(bundle).objects:
        if o.type.name == "AssetBundle":
            return any(k == path for k, _ in o.read().m_Container)
    return False


class Game:
    def __init__(self, root):
        self.root = Path(root).resolve()
        if not (self.root / "AzurPromiliaJP.exe").is_file():
            sys.exit(f"AzurPromiliaJP.exe not found in {self.root}")
        d = self.root / "AzurPromiliaJP_Data"
        self.cache, self.builtin = d / ".res", d / "StreamingAssets" / ".res"

    def rel(self, p):
        return str(Path(p).relative_to(self.root))

    def manifest(self, pkg):
        name = f"0release_{pkg}_*.bytes"
        c = [*(self.cache / pkg / "ManifestFiles").glob(name), *(self.builtin / pkg).glob(name)]
        if not c:
            sys.exit(f"no {pkg} manifest found; finish the game download first")
        return max(c, key=lambda p: int(p.stem.rsplit("_", 1)[1])).read_bytes()

    def files(self, pkg):
        for d in (self.cache / pkg / "BundleFiles", self.builtin / pkg):
            if d.is_dir():
                yield from sorted(d.glob("*.r"))


def load_key(game, state):
    arcs = [p for p in game.files("raw_base_package") if p.open("rb").read(8) == MMAP_MAGIC]
    if not arcs:
        sys.exit("no MMap archives found")
    kp = state / "mmap_key.bin"
    K = kp.read_bytes() if kp.exists() else None
    pools = [p for p in arcs if K and is_pool(p.read_bytes(), K)]
    if not pools:
        print(f"Recovering archive key from {len(arcs)} archives (about a minute)...")
        K = recover_key(arcs)
        state.mkdir(parents=True, exist_ok=True)
        write(kp, K)
        pools = [p for p in arcs if is_pool(p.read_bytes(), K)]
    if not pools:
        sys.exit("vstring.bytes not found")
    return K, min(pools, key=lambda p: game.cache not in p.parents)


def find_menu(game, pool):
    pid = next((i for i in range(pool.count) if pool.get(i) == MENU_PATH), None)
    if pid is None:
        sys.exit("menu text asset not found in vstring")
    size, off = manifest_bundle(game.manifest("default_package"), pid)
    for p in game.files("default_package"):
        if p.stat().st_size >= off + size:
            with p.open("rb") as f:
                f.seek(off)
                c = f.read(size)
            if c[:7] == b"UnityFS" and has_container(c, MENU_PATH.decode()):
                return p, off, size
    sys.exit("menu text bundle not found")


def load_catalog(path):
    with zipfile.ZipFile(path) as z:
        es = json.loads(gzip.decompress(z.read("english.catalog.json.gz")))["entries"]
    gp = {e["source_sha256"]: e["en"] for e in es if e["table"] == "gameplay"}
    menu = {e["key"][len(MENU_PREFIX):]: (e["source_sha256"], e["en"]) for e in es
            if e["table"] == "static_ui" and e["key"].startswith(MENU_PREFIX)}
    return gp, menu


class State:
    def __init__(self, path):
        self.dir = Path(path)
        self.record = self.dir / "applied.json"
        self.backup = self.dir / "backup"

    def load(self):
        return json.loads(self.record.read_text("utf-8")) if self.record.exists() else None

    def clear(self):
        self.record.unlink(missing_ok=True)
        shutil.rmtree(self.backup, ignore_errors=True)


def file_states(rec, root):
    out = {}
    for rel, r in rec["files"].items():
        cur = sha_file(Path(root) / rel)
        out[rel] = {None: "missing", r["patched_sha256"]: "patched", r["original_sha256"]: "original"}.get(cur, "changed")
    return out


def ensure_closed():
    tasks = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True).stdout.lower()
    running = [p for p in PROCS if f'"{p}"' in tasks]
    if running:
        sys.exit("Close these first: " + ", ".join(running))


def ensure_writable(paths):
    for p in paths:
        try:
            open(f"{p}.azp-probe", "wb").close()
            os.remove(f"{p}.azp-probe")
        except PermissionError:
            sys.exit(f"Write access denied to {Path(p).parent}\nRun as administrator. Nothing was changed.")


def plan(a):
    game, st = Game(a.game), State(a.state)
    gp, menu = load_catalog(a.data)
    K, vpath = load_key(game, st.dir)
    vraw = vpath.read_bytes()
    pool = VString(vraw, K)
    pack, off, slot = find_menu(game, pool)
    print(f"gameplay text : {game.rel(vpath)} ({pool.count:,} strings)")
    print(f"menu text     : {game.rel(pack)} (bundle at {off:,}, {slot:,} bytes)")
    print(f"catalog       : {len(gp):,} gameplay, {len(menu):,} menu entries")
    return game, st, K, gp, menu, vpath, vraw, pool, pack, off, slot


def cmd_check(a):
    rec = State(a.state).load()
    for rel, s in (file_states(rec, a.game) if rec else {}).items():
        print(f"recorded file {s:9}: {rel}")
    plan(a)
    print("check ok")


def cmd_apply(a):
    ensure_closed()
    st = State(a.state)
    rec = st.load()
    if rec:
        states = file_states(rec, a.game).values()
        if "patched" in states:
            sys.exit("Already applied. Run `restore` first.")
        print("Previous patch was replaced by a game update or repair; discarding old record.")
        st.clear()
    game, st, K, gp, menu, vpath, vraw, pool, pack, off, slot = plan(a)

    print("Building...")
    vnew = pool.build(K, gp)
    praw = pack.read_bytes()
    bundle, raw_new = translate_menu(praw[off:off + slot], menu)
    if len(bundle) > slot:
        sys.exit("menu bundle does not fit its slot; nothing was changed")
    if menu_object(bundle)[1].get_raw_data() != raw_new:
        sys.exit("menu bundle readback failed; nothing was changed")
    pnew = praw[:off] + bundle.ljust(slot, b"\0") + praw[off + slot:]

    jobs = [(vpath, vraw, vnew), (pack, praw, pnew)]
    ensure_writable([vpath, pack])
    rec = {"game": str(game.root), "files": {}}
    for p, old, new in jobs:
        rel = game.rel(p)
        bk = st.backup / rel
        bk.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, bk)
        if sha_file(bk) != sha(old):
            sys.exit(f"backup verification failed for {rel}; nothing was changed")
        rec["files"][rel] = {"original_sha256": sha(old), "patched_sha256": sha(new)}
    st.record.write_text(json.dumps(rec, indent=2), "utf-8")
    done = []
    try:
        for p, _, new in jobs:
            write(p, new)
            done.append(p)
    except Exception as e:
        for p in done:
            shutil.copy2(st.backup / game.rel(p), p)
        for p, _, _ in jobs:
            Path(f"{p}.azp-tmp").unlink(missing_ok=True)
        st.record.unlink()
        sys.exit(f"Writing failed ({e}); game files restored.")
    if any(s != "patched" for s in file_states(rec, game.root).values()):
        sys.exit("verification failed; run `restore`")
    print("English applied.")


def cmd_restore(a):
    st = State(a.state)
    rec = st.load()
    if not rec:
        sys.exit("Nothing to restore.")
    root = Path(a.game or rec["game"]).resolve()
    ensure_closed()
    ensure_writable([root / r for r in rec["files"]])
    for rel, s in file_states(rec, root).items():
        if s != "patched":
            print(f"   skipped ({s}): {rel}")
            continue
        orig = rec["files"][rel]["original_sha256"]
        if sha_file(st.backup / rel) != orig:
            sys.exit(f"backup for {rel} is damaged; repair the game in the launcher")
        shutil.copy2(st.backup / rel, f"{root / rel}.azp-tmp")
        os.replace(f"{root / rel}.azp-tmp", root / rel)
        if sha_file(root / rel) != orig:
            sys.exit(f"restore failed for {rel}; repair the game in the launcher")
        print("   restored", rel)
    st.clear()
    print("Japanese restored.")


def cmd_fetch(a):
    get = lambda u, t: urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "azp-patcher"}), timeout=t)
    d = json.load(get(CHANNEL, 30))["data"]
    if not d["url"].startswith(DATA_PREFIX) or not d["url"].endswith("/english-data.zip"):
        sys.exit("unexpected data URL: " + d["url"])
    dest = Path(a.data)
    if sha_file(dest) == d["sha256"]:
        print("Already up to date:", d["version"])
        return
    print("Downloading", d["version"])
    blob = get(d["url"], 120).read()
    if len(blob) != d["size"] or sha(blob) != d["sha256"]:
        sys.exit("download does not match published size/SHA-256")
    dest.parent.mkdir(parents=True, exist_ok=True)
    write(dest, blob)
    print("Saved", dest)


def ask_game():
    if (DEFAULT_GAME / "AzurPromiliaJP.exe").is_file():
        return DEFAULT_GAME
    return input("Game folder (the one with AzurPromiliaJP.exe): ").strip().strip('"')


def interactive(a):
    c = input("1) Install English  2) Restore Japanese\n> ").strip()
    if c == "1":
        a.game = ask_game()
        cmd_fetch(a)
        cmd_apply(a)
    elif c == "2":
        cmd_restore(a)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command", nargs="?", choices=["check", "apply", "restore", "fetch"])
    ap.add_argument("--game")
    ap.add_argument("--data", default=HERE / "data" / "english-data.zip")
    ap.add_argument("--state", default=HERE / "state")
    a = ap.parse_args()
    if not a.command:
        try:
            interactive(a)
        except SystemExit as e:
            if e.code:
                print(e.code)
        except Exception as e:
            print("Error:", e)
        input("Press Enter to exit.")
        return
    if a.command in ("check", "apply") and not a.game:
        a.game = ask_game()
    globals()["cmd_" + a.command](a)


if __name__ == "__main__":
    main()
