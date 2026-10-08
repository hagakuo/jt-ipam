"""最小 Guacamole 協定客戶端：經 guacd 連 RDP／VNC／SSH、打一行字、把畫面合成成 PNG。

給 scripts/guacd/verify.sh 驗預編檔用 —— 「guacd 跑得起來、外掛載得到」不代表連得上：
1.6.0 在 Ubuntu 26.04 上外掛載得到，一畫第一個畫面就 segfault。一定要真的連一次。

用法：guacli.py <guacd 埠> <輸出 png> <rdp|vnc|ssh> <主機> <埠> <帳號> <密碼>
（VNC 的測試靶不理會輸入，所以 VNC 只驗畫面，不打字）
兩個坑（2026-09-25 試作時踩到）：
- guacd 要客戶端定期送東西（官方 JS 每幾秒送 nop），否則判定「User is not responding」斷線。
- 解析要增量；每次重解整個緩衝會慢到跟不上，也會被當成沒回應。
"""
import base64, codecs, collections, contextlib, io, socket, sys, time
from PIL import Image

PORT, OUT, PROTO = int(sys.argv[1]), sys.argv[2], sys.argv[3]
T_HOST, T_PORT, T_USER, T_PASS = sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7]
s = socket.create_connection(("127.0.0.1", PORT), timeout=1)
dec = codecs.getincrementaldecoder("utf-8")()
buf, pos = "", 0

def enc(*parts):
    return (",".join(f"{len(p)}.{p}" for p in parts) + ";").encode()

def try_parse():
    """從 buf[pos:] 切出一條完整指令；不完整回 None（值以長度前綴切，含 ; 也不怕）"""
    global pos
    i, out = pos, []
    while True:
        dot = buf.find(".", i)
        if dot < 0: return None
        n = int(buf[i:dot]); end = dot + 1 + n
        if end >= len(buf): return None
        out.append(buf[dot + 1:end])
        if buf[end] == ";":
            pos = end + 1
            return out
        i = end + 1

def read_instr(deadline):
    global buf, pos
    while True:
        ins = try_parse()
        if ins is not None: return ins
        if pos > 1 << 20: buf, pos = buf[pos:], 0
        if time.time() > deadline: return None
        try:
            chunk = s.recv(262144)
        except socket.timeout:
            return ["__idle__"]
        if not chunk: raise EOFError
        buf += dec.decode(chunk)

s.sendall(enc("select", PROTO))
args = read_instr(time.time() + 10)
if not args or args[0] != "args":
    sys.exit(f"guacd 沒有回 args：{args}")
vals = {"hostname": T_HOST, "port": T_PORT, "username": T_USER, "password": T_PASS}
if PROTO == "rdp":
    vals.update({"security": "any", "ignore-cert": "true", "disable-audio": "true"})
elif PROTO == "ssh":
    vals.update({"font-name": "monospace", "font-size": "12"})
s.sendall(enc("size", "1024", "600", "96") + enc("audio") + enc("video")
          + enc("image", "image/png", "image/jpeg", "image/webp"))
t0 = time.time()
s.sendall(enc("connect", *[("VERSION_1_5_0" if n.startswith("VERSION_") else vals.get(n, "")) for n in args[1:]]))

# 圖層合成：guacd 的終端機（SSH）先把字畫在暫存圖層（負數編號），再 copy 到畫面（0 號）。
# 只合成直接畫在 0 號的圖，SSH 會是一片黑卻照樣「有畫面」—— 驗證形同沒驗（2026-09-25 踩到）。
layers: dict[str, Image.Image] = {"0": Image.new("RGBA", (1024, 600), (0, 0, 0, 255))}
path: dict[str, tuple[int, int, int, int]] = {}
#: 可見圖層（正數編號）的位置與前後順序：move(layer, parent, x, y, z)。終端機（SSH）就畫在這種圖層上
moves: dict[str, tuple[int, int, int]] = {}


def layer(idx: str) -> Image.Image:
    if idx not in layers:
        layers[idx] = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    return layers[idx]


def ensure(idx: str, w: int, h: int) -> Image.Image:
    im = layer(idx)
    if im.width < w or im.height < h:
        bigger = Image.new("RGBA", (max(im.width, w), max(im.height, h)), (0, 0, 0, 0))
        bigger.paste(im, (0, 0))
        layers[idx] = im = bigger
    return im


def copy_region(src: str, sx: int, sy: int, w: int, h: int, dst: str, dx: int, dy: int) -> None:
    if w <= 0 or h <= 0:
        return
    region = layer(src).crop((sx, sy, sx + w, sy + h))
    ensure(dst, dx + w, dy + h).paste(region, (dx, dy), region)


streams, ops = {}, collections.Counter()
t_ready = t_first_img = None; n_img = n_bytes = 0; typed = False; err = None; last_nop = 0
deadline = time.time() + 30
while time.time() < deadline:
    if time.time() - last_nop > 2:
        s.sendall(enc("nop")); last_nop = time.time()
    try:
        ins = read_instr(deadline)
    except EOFError:
        err = "EOF"; break
    if ins is None: break
    op = ins[0]; ops[op] += 1
    try:
        if op == "ready": t_ready = time.time() - t0
        elif op == "sync": s.sendall(enc("sync", ins[1]))
        elif op == "error": err = f"guacd error: {ins[1:]}"; break
        elif op == "disconnect": err = "disconnect"; break
        elif op == "size":
            idx, w, h = ins[1], int(ins[2]), int(ins[3])
            im = layer(idx)
            resized = Image.new("RGBA", (max(1, w), max(1, h)), (0, 0, 0, 255 if idx == "0" else 0))
            resized.paste(im, (0, 0))
            layers[idx] = resized
        elif op == "img":
            streams[ins[1]] = {"layer": ins[3], "x": int(ins[5]), "y": int(ins[6]), "data": []}
        elif op == "blob" and ins[1] in streams:
            streams[ins[1]]["data"].append(ins[2])
        elif op == "end" and ins[1] in streams:
            st = streams.pop(ins[1])
            raw = base64.b64decode("".join(st["data"]))
            n_img += 1; n_bytes += len(raw)
            if t_first_img is None: t_first_img = time.time() - t0
            with contextlib.suppress(Exception):
                pic = Image.open(io.BytesIO(raw)).convert("RGBA")
                ensure(st["layer"], st["x"] + pic.width, st["y"] + pic.height).paste(pic, (st["x"], st["y"]), pic)
        elif op in ("copy", "transfer"):
            # copy: src sx sy w h mask dst dx dy ／ transfer: src sx sy w h func dst dx dy
            copy_region(ins[1], int(ins[2]), int(ins[3]), int(ins[4]), int(ins[5]), ins[7], int(ins[8]), int(ins[9]))
        elif op == "move":
            moves[ins[1]] = (int(ins[3]), int(ins[4]), int(ins[5]))
        elif op == "dispose":
            layers.pop(ins[1], None); moves.pop(ins[1], None)
        elif op == "rect":
            path[ins[1]] = (int(ins[2]), int(ins[3]), int(ins[4]), int(ins[5]))
        elif op == "cfill" and ins[2] in path:
            x, y, w, h = path.pop(ins[2])
            color = (int(ins[3]), int(ins[4]), int(ins[5]), int(ins[6]))
            ensure(ins[2], x + w, y + h).paste(Image.new("RGBA", (max(1, w), max(1, h)), color), (x, y))
            if t_first_img is None: t_first_img = time.time() - t0
    except (ValueError, IndexError):
        pass
    # 第一張畫面出來 5 秒後打一行字，看鍵盤有沒有送到（VNC 的測試靶不理會輸入）
    if PROTO != "vnc" and t_first_img and not typed and time.time() - t0 > t_first_img + 5:
        typed = True
        for ch in "echo guacd-ok":
            s.sendall(enc("key", str(ord(ch)), "1") + enc("key", str(ord(ch)), "0"))
        s.sendall(enc("key", "65293", "1") + enc("key", "65293", "0"))   # Return
    if typed and time.time() - t0 > t_first_img + 12:
        break
    if PROTO == "vnc" and t_first_img and time.time() - t0 > t_first_img + 4:
        break
# 畫面＝0 號圖層，再依 z 疊上可見圖層（負數是看不見的暫存區，不疊）
canvas = layers["0"].copy()
visible = [k for k in layers if k.lstrip("-").isdigit() and int(k) > 0]
for k in sorted(visible, key=lambda k: moves.get(k, (0, 0, 0))[2]):
    x, y, _z = moves.get(k, (0, 0, 0))
    canvas.paste(layers[k], (x, y), layers[k])
canvas = canvas.convert("RGB")
canvas.save(OUT)
s.sendall(enc("disconnect"))
top = ",".join(f"{k}:{v}" for k, v in ops.most_common(6) if k != "__idle__")
# 畫面上非黑像素的比例：全黑＝其實什麼都沒畫出來（verify 用它擋「有指令、沒內容」）
# 用絕對像素數而不是百分比：黑底終端機只有幾行字，比例不到 1%，但那是正常畫面
painted = sum(1 for p in canvas.getdata() if p != (0, 0, 0))
print(f"ready_s={t_ready and round(t_ready, 2)} first_img_s={t_first_img and round(t_first_img, 2)} "
      f"images={n_img} painted_px={painted} bytes={n_bytes} typed={typed} err={err} ops={top}")
