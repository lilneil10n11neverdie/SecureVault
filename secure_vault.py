# -*- coding: utf-8 -*-
"""
本地加密保险箱 (Secure Vault)
================================
- 使用 AES-256-GCM 认证加密算法加密图片、视频等任意文件
- 密码经 PBKDF2-HMAC-SHA256（600,000 次迭代）派生 256 位密钥
- 密码错误时解密在密码学层面直接失败，无法查看内容（不可绕过）
- 加密文件自带原始文件名（加密存储），解密后自动恢复原文件名
- 「预览」模式：解密到临时目录打开查看，用完一键彻底清除
- 「安全删除」：覆写随机数据后删除原文件

加密文件格式（.svenc）：
    MAGIC(9) | salt(16) | nonce(12) | ciphertext | GCM-tag(16)
    其中 ciphertext = AES-256-GCM( 校验值(16) | 文件名长度(4) | 文件名UTF-8 | 文件内容 )

用法：
    python secure_vault.py            # 启动图形界面
    python secure_vault.py --selftest # 运行自检（加密/解密往返测试）
"""

from __future__ import annotations

import hashlib
import os
import queue
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

APP_NAME = "本地加密保险箱"
MAGIC = b"SECVAULT1"
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
VERIF_LEN = 16
KDF_ITER = 600_000
CHUNK = 1 << 20  # 1 MiB 读写块
EXT = ".svenc"
PLACEHOLDER = "（空）点击右上「添加文件 / 添加文件夹」选择要处理的文件"
VERBS = {"enc": "加密", "dec": "解密", "view": "预览"}

MEDIA_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".avif", ".tiff", ".ico",
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".ts", ".mpg",
    ".mpeg", ".3gp", ".rmvb",
}

# ---------------------------------------------------------------------------
# 配色 / 字体
# ---------------------------------------------------------------------------
BG        = "#171A21"   # 窗口背景
HEADER    = "#1E222C"   # 顶栏
CARD      = "#222733"   # 卡片
FIELD     = "#2B3140"   # 输入框
FIELD_HV  = "#353C4E"
LIST_BG   = "#1C202A"   # 列表背景
LOG_BG    = "#141720"   # 日志背景
BORDER_S  = "#394154"
ACCENT    = "#5B8CFF"   # 主题蓝
ACCENT_HV = "#7AA3FF"
GREEN     = "#6FDB9B"
RED       = "#FF8B96"
AMBER     = "#FFC46B"
TEXT      = "#E9ECF4"
MUTED     = "#97A0B5"
FAINT     = "#6C7488"

FONT      = ("Microsoft YaHei UI", 10)
FONT_SM   = ("Microsoft YaHei UI", 9)
FONT_XS   = ("Microsoft YaHei UI", 8)
FONT_BOLD = ("Microsoft YaHei UI", 10, "bold")
FONT_LOG  = ("Consolas", 9)


class PasswordError(Exception):
    """密码错误（密钥校验值不匹配）"""


class VaultError(Exception):
    """文件格式无效或已损坏"""


class Cancelled(Exception):
    """用户取消"""


# ---------------------------------------------------------------------------
# 核心加密 / 解密
# ---------------------------------------------------------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, KDF_ITER, 32)


def verifier_bytes(key: bytes) -> bytes:
    return hashlib.sha256(b"SVCHK1" + key).digest()[:VERIF_LEN]


def unique_path(directory: Path, name: str) -> Path:
    p = directory / name
    if not p.exists():
        return p
    stem, suf = os.path.splitext(name)
    i = 1
    while True:
        p = directory / f"{stem} ({i}){suf}"
        if not p.exists():
            return p
        i += 1


def secure_delete(path: Path, chunk: int = CHUNK) -> bool:
    """尽力而为的『安全删除』：先覆写随机数据，再改名并删除。
    注意：SSD / 开启 TRIM 的盘上任何软件都无法保证绝对不可恢复。"""
    try:
        size = path.stat().st_size
        with open(path, "rb+") as f:
            written = 0
            while written < size:
                n = min(chunk, size - written)
                f.write(os.urandom(n))
                written += n
            f.flush()
            os.fsync(f.fileno())
        path.rename(path.with_name(f"~sv{os.urandom(6).hex()}.tmp"))
    except OSError:
        pass
    try:
        path.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def encrypt_file(src: Path, dst: Path, key: bytes, salt: bytes,
                 report=None, cancel: threading.Event | None = None) -> None:
    """把 src 加密写入 dst（流式处理，支持大文件）。"""
    nonce = os.urandom(NONCE_LEN)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    tmp = dst.with_name(dst.name + ".part")
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            fout.write(MAGIC)
            fout.write(salt)
            fout.write(nonce)
            name = src.name.encode("utf-8")
            head = verifier_bytes(key) + len(name).to_bytes(4, "big") + name
            fout.write(enc.update(head))
            while True:
                if cancel is not None and cancel.is_set():
                    raise Cancelled()
                buf = fin.read(CHUNK)
                if not buf:
                    break
                fout.write(enc.update(buf))
                if report is not None:
                    report(len(buf))
            fout.write(enc.finalize())
            fout.write(enc.tag)
        os.replace(tmp, dst)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _split_head(pend: bytes, key: bytes):
    """尝试从已解密缓冲区解析出文件名；数据不足返回 None。"""
    need = VERIF_LEN + 4
    if len(pend) < need:
        return None
    if pend[:VERIF_LEN] != verifier_bytes(key):
        raise PasswordError("密码错误")
    fn_len = int.from_bytes(pend[VERIF_LEN:need], "big")
    if fn_len <= 0 or fn_len > 1024:
        raise VaultError("加密文件头损坏")
    if len(pend) < need + fn_len:
        return None
    fname = pend[need:need + fn_len].decode("utf-8", "replace")
    fname = fname.replace("/", "_").replace("\\", "_").replace("\x00", "_")
    return fname, pend[need + fn_len:]


def decrypt_file(src: Path, dst_dir: Path, password: str,
                 report=None, cancel: threading.Event | None = None) -> Path:
    """用密码解密 src，把结果写入 dst_dir 并恢复原始文件名。返回输出路径。"""
    try:
        size = src.stat().st_size
    except OSError as e:
        raise VaultError(f"无法读取 {src.name}: {e}")
    min_len = len(MAGIC) + SALT_LEN + NONCE_LEN + TAG_LEN + 24
    if size < min_len:
        raise VaultError(f"{src.name} 不是有效的加密文件")

    fd, tmp_name = tempfile.mkstemp(prefix=".svtmp_", dir=dst_dir)
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        with open(src, "rb") as fin:
            head = fin.read(len(MAGIC) + SALT_LEN + NONCE_LEN)
            if head[:len(MAGIC)] != MAGIC:
                raise VaultError(f"{src.name} 不是有效的加密文件（缺少标识头）")
            salt = head[len(MAGIC):len(MAGIC) + SALT_LEN]
            nonce = head[len(MAGIC) + SALT_LEN:]
            key = derive_key(password, salt)

            fin.seek(size - TAG_LEN)
            tag = fin.read(TAG_LEN)
            body_start = len(MAGIC) + SALT_LEN + NONCE_LEN
            fin.seek(body_start)
            remaining = size - body_start - TAG_LEN

            dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            hdr: str | None = None
            pend = b""
            with open(tmp, "wb") as fout:
                while remaining > 0:
                    if cancel is not None and cancel.is_set():
                        raise Cancelled()
                    n = min(CHUNK, remaining)
                    data = fin.read(n)
                    if len(data) != n:
                        raise VaultError(f"{src.name} 文件不完整")
                    remaining -= n
                    pt = dec.update(data)
                    if report is not None:
                        report(n)
                    if hdr is None:
                        pend += pt
                        r = _split_head(pend, key)
                        if r is not None:
                            hdr, rest = r
                            pend = b""
                            if rest:
                                fout.write(rest)
                    else:
                        fout.write(pt)
                try:
                    tail = dec.finalize()
                except InvalidTag:
                    raise VaultError(f"{src.name} 已损坏或被篡改（完整性校验失败）")
                if hdr is None:
                    r = _split_head(pend + tail, key)
                    if r is None:
                        raise VaultError(f"{src.name} 文件内容为空或已损坏")
                    hdr, rest = r
                    if rest:
                        fout.write(rest)
                elif tail:
                    fout.write(tail)
        out = unique_path(dst_dir, hdr)
        os.replace(tmp, out)
        return out
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

def selftest() -> int:
    import random
    rng = random.Random(2026)
    tmp = Path(tempfile.mkdtemp(prefix="svtest_"))
    ok = True
    try:
        img = tmp / "照片 test.jpg"
        img.write_bytes(b"\xff\xd8\xff\xe0JFIF" + rng.randbytes(300_000))
        vid = tmp / "视频 test.mp4"
        vid.write_bytes(rng.randbytes(3_000_000))
        pw = "正确密码Abc123!"
        salt = os.urandom(SALT_LEN)
        key = derive_key(pw, salt)

        c1 = tmp / (img.name + EXT)
        c2 = tmp / (vid.name + EXT)
        encrypt_file(img, c1, key, salt)
        encrypt_file(vid, c2, key, salt)

        checks = []
        checks.append((c1.read_bytes()[:9] == MAGIC, "文件头正确"))
        checks.append((c1.stat().st_size > img.stat().st_size, "加密后体积增大"))
        checks.append((c1.read_bytes().find(img.read_bytes()[100:400]) == -1,
                       "密文不含明文片段"))

        try:
            decrypt_file(c1, tmp, "错误密码000")
            checks.append((False, "错误密码必须被拒绝"))
        except PasswordError:
            checks.append((True, "错误密码被拒绝"))

        # 随机命名密文也能恢复原文件名
        c3 = tmp / (f"SV-{os.urandom(4).hex().upper()}" + EXT)
        encrypt_file(img, c3, key, salt)
        out3 = decrypt_file(c3, tmp, pw)
        checks.append((out3.name.startswith("照片 test") and
                       out3.read_bytes() == img.read_bytes(),
                       "随机命名密文恢复原文件名"))

        # 解密到独立目录（预览模式路径）
        vdir = tmp / "view"
        vdir.mkdir()
        outv = decrypt_file(c2, vdir, pw)
        checks.append((outv.parent == vdir and outv.read_bytes() == vid.read_bytes(),
                       "解密到指定目录"))

        for orig, c in ((img, c1), (vid, c2)):
            out = decrypt_file(c, tmp, pw)
            checks.append((out.read_bytes() == orig.read_bytes(),
                           f"往返一致 {orig.name} -> {out.name}"))

        raw = bytearray(c1.read_bytes())
        raw[-3] ^= 0xFF
        tam = tmp / "tampered.svenc"
        tam.write_bytes(raw)
        try:
            decrypt_file(tam, tmp, pw)
            checks.append((False, "篡改必须被检测"))
        except (VaultError, PasswordError):
            checks.append((True, "篡改被检测"))

        dj = tmp / "delme.bin"
        dj.write_bytes(rng.randbytes(5000))
        secure_delete(dj)
        checks.append((not dj.exists(), "安全删除生效"))

        for good, msg in checks:
            ok &= good
            print(("[PASS] " if good else "[FAIL] ") + msg)
        print("=== ALL PASS ===" if ok else "=== SOME TESTS FAILED ===")
        return 0 if ok else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# 图形界面
# ---------------------------------------------------------------------------

def make_icon(size: int = 32) -> tk.PhotoImage:
    """程序化绘制盾牌图标（蓝盾 + 钥匙孔）。"""
    img = tk.PhotoImage(width=size, height=size)
    fill, edge, hole, hi = "#5B8CFF", "#2E4CA8", "#10131A", "#7AA3FF"
    s = size / 32.0
    pts = [(3 * s, 7.0 * s), (5 * s, 10.5 * s), (8 * s, 12.0 * s),
           (14 * s, 13.2 * s), (20 * s, 11.0 * s), (25 * s, 6.0 * s),
           (28 * s, 1.2 * s)]

    def hw(y: float) -> float:
        if y < pts[0][0]:
            return 0.0
        for (y0, w0), (y1, w1) in zip(pts, pts[1:]):
            if y <= y1:
                t = (y - y0) / (y1 - y0)
                return w0 + (w1 - w0) * t
        return 0.0

    cx = (size - 1) / 2.0
    for y in range(size):
        w = hw(y)
        if w <= 0:
            continue
        for x in range(size):
            dx = abs(x - cx)
            if dx > w:
                continue
            border = dx > w - 1.5 * s or y <= 3.5 * s
            if border:
                c = edge
            elif (x - cx) ** 2 + (y - 12.5 * s) ** 2 <= (3.1 * s) ** 2 or (
                    cx - 0.9 * s <= x <= cx + 0.9 * s and 14 * s <= y <= 19 * s):
                c = hole
            elif y < 11 * s and dx < w - 2.5 * s:
                c = hi
            else:
                c = fill
            img.put(c, (x, y))
    return img


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} — 图片 / 视频本地加密")
        try:
            scale = self.winfo_fpixels("1i") / 96.0
        except tk.TclError:
            scale = 1.0
        self.geometry(f"{int(830 * scale)}x{int(645 * scale)}")
        self.minsize(int(700 * scale), int(560 * scale))
        self.configure(bg=BG)
        try:
            self.icon = make_icon(32)
            self.iconphoto(True, self.icon)
        except tk.TclError:
            self.icon = None

        self._setup_style()

        self.q: queue.Queue = queue.Queue()
        self.cancel_ev = threading.Event()
        self.worker: threading.Thread | None = None
        self.total_bytes = 1
        self.last_out_dir: str | None = None
        self._pending_error: str | None = None
        self._cur_mode = "enc"
        self._cur_file = ""
        self._pct = 0.0

        # 预览（临时解密）状态
        self.preview_dir: Path | None = None
        self.preview_files: list[Path] = []
        self.preview_win: tk.Toplevel | None = None

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._build_ui()

    # ----- 样式 -----------------------------------------------------------

    def _setup_style(self):
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        self.style = st

        st.configure(".", background=BG, foreground=TEXT, font=FONT,
                     borderwidth=0, focuscolor=ACCENT)
        st.configure("TFrame", background=BG)
        st.configure("Header.TFrame", background=HEADER)
        st.configure("Header.TLabel", background=HEADER, foreground=TEXT)
        st.configure("HeaderSub.TLabel", background=HEADER, foreground=FAINT, font=FONT_SM)
        st.configure("Chip.TLabel", background="#2A3140", foreground=ACCENT, font=FONT_XS,
                     padding=(8, 3))
        st.configure("TLabel", background=BG, foreground=TEXT)
        st.configure("Status.TLabel", background=BG, foreground=MUTED, font=FONT_SM)

        # 卡片
        st.configure("Card.TLabelframe", background=CARD, borderwidth=1,
                     relief="solid", bordercolor=BORDER_S)
        st.configure("Card.TLabelframe.Label", background=CARD, foreground=MUTED,
                     font=("Microsoft YaHei UI", 9, "bold"), padding=(2, 0))
        st.configure("Card.TFrame", background=CARD)
        st.configure("CardMuted.TLabel", background=CARD, foreground=MUTED, font=FONT_SM)
        st.configure("CardFaint.TLabel", background=CARD, foreground=FAINT, font=FONT_XS)
        st.configure("Strength.TLabel", background=CARD, font=FONT_SM, foreground=MUTED)

        # 按钮
        st.configure("TButton", background="#2F3646", foreground="#D6DCEA", font=FONT,
                     borderwidth=1, relief="solid", bordercolor="#454E63",
                     lightcolor="#2F3646", darkcolor="#2F3646", padding=(14, 7),
                     focuscolor="#2F3646")
        st.map("TButton",
               background=[("pressed", "#3D4557"), ("active", "#3B4356"),
                           ("disabled", "#262B37")],
               foreground=[("disabled", "#6C7488")],
               bordercolor=[("pressed", "#4E5870"), ("active", "#4E5870")])

        st.configure("Primary.TButton", background=ACCENT, foreground="white",
                     font=("Microsoft YaHei UI", 11, "bold"), padding=(28, 9),
                     bordercolor=ACCENT, lightcolor=ACCENT, darkcolor=ACCENT)
        st.map("Primary.TButton",
               background=[("pressed", "#4A79E8"), ("active", ACCENT_HV),
                           ("disabled", "#39415A")],
               foreground=[("disabled", "#8A93A8")],
               bordercolor=[("pressed", ACCENT_HV)],
               lightcolor=[("pressed", "#4A79E8"), ("active", ACCENT_HV)],
               darkcolor=[("pressed", "#4A79E8"), ("active", ACCENT_HV)])

        st.configure("View.TButton", background="#1F3A2E", foreground=GREEN,
                     font=("Microsoft YaHei UI", 11, "bold"), padding=(20, 9),
                     bordercolor="#2E5943", lightcolor="#1F3A2E", darkcolor="#1F3A2E")
        st.map("View.TButton",
               background=[("pressed", "#173025"), ("active", "#27493A"),
                           ("disabled", "#22302B")],
               foreground=[("disabled", "#4E6B5E")],
               bordercolor=[("pressed", "#3B6E52"), ("active", "#3B6E52")])

        st.configure("Danger.TButton", background="#3A2A33", foreground=RED, font=FONT_SM,
                     bordercolor="#57394A", lightcolor="#3A2A33", darkcolor="#3A2A33",
                     padding=(12, 5))
        st.map("Danger.TButton",
               background=[("pressed", "#4A3542"), ("active", "#4A3542"),
                           ("disabled", "#2A2530")],
               foreground=[("disabled", "#6C545E")])

        # 输入框
        st.configure("TEntry", fieldbackground=FIELD, foreground=TEXT,
                     insertcolor=TEXT, borderwidth=1, relief="solid",
                     bordercolor=BORDER_S, lightcolor=FIELD, darkcolor=FIELD,
                     padding=(9, 7))
        st.map("TEntry",
               bordercolor=[("focus", ACCENT)],
               lightcolor=[("focus", FIELD)], darkcolor=[("focus", FIELD)],
               fieldbackground=[("disabled", "#232833")],
               foreground=[("disabled", "#6C7488")])

        # 复选框
        st.configure("Card.TCheckbutton", background=CARD, foreground=MUTED, font=FONT_SM,
                     focuscolor=CARD, padding=2)
        st.map("Card.TCheckbutton",
               background=[("active", CARD)],
               foreground=[("selected", TEXT), ("active", TEXT)],
               indicatorcolor=[("selected", ACCENT)])

        # 标签页
        st.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(10, 8, 10, 0))
        st.configure("TNotebook.Tab", background="#1B1F27", foreground="#7E879C",
                     font=("Microsoft YaHei UI", 10, "bold"), padding=(20, 9),
                     borderwidth=0, focuscolor="#1B1F27")
        st.map("TNotebook.Tab",
               background=[("selected", "#2E3650"), ("active", "#242A38")],
               foreground=[("selected", "#FFFFFF"), ("active", "#C6CDDC")])

        # 滚动条（深色）
        st.configure("Vertical.TScrollbar", background="#3A4254",
                     troughcolor=LIST_BG, bordercolor=BG, lightcolor="#3A4254",
                     darkcolor="#3A4254", arrowcolor=MUTED, borderwidth=0,
                     relief="flat", arrowsize=11)
        st.map("Vertical.TScrollbar",
               background=[("pressed", "#4C5670"), ("active", "#465064")])

        # 进度条
        st.configure("SV.Horizontal.TProgressbar", background=ACCENT,
                     troughcolor="#242A37", bordercolor=BG, lightcolor=ACCENT,
                     darkcolor=ACCENT, thickness=10)

    # ----- 界面搭建 -------------------------------------------------------

    def _header(self):
        hd = ttk.Frame(self, style="Header.TFrame", padding=(20, 14, 20, 12))
        hd.pack(fill="x")
        try:
            tk.Label(hd, text="\U0001F6E1", bg=HEADER, fg=TEXT,
                     font=("Segoe UI Emoji", 24)).pack(side="left", padx=(0, 12))
        except tk.TclError:
            pass
        box = ttk.Frame(hd, style="Header.TFrame")
        box.pack(side="left")
        ttk.Label(box, text="本地加密保险箱", style="Header.TLabel",
                  font=("Microsoft YaHei UI", 15, "bold")).pack(anchor="w")
        ttk.Label(box, text="AES-256-GCM 认证加密 · 全程离线 · 文件不离开本机",
                  style="HeaderSub.TLabel").pack(anchor="w", pady=(2, 0))
        ttk.Label(hd, text="🔒 AES-256", style="Chip.TLabel").pack(side="right")

    def _build_ui(self):
        self._header()

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=14, pady=(4, 6))

        # ===== 加密页 =====
        enc = ttk.Frame(nb, padding=(4, 10))
        nb.add(enc, text="  🔒  加密  ")

        bar = ttk.Frame(enc)
        bar.pack(fill="x")
        for text, cmd in (("＋ 添加文件", self._enc_add_files),
                          ("📂 添加文件夹（图片/视频）", self._enc_add_folder)):
            ttk.Button(bar, text=text, command=cmd).pack(side="left")
        ttk.Button(bar, text="移除选中",
                   command=lambda: self._remove_selected(self.enc_list)).pack(side="right")
        ttk.Button(bar, text="清空列表",
                   command=lambda: self._clear_list(self.enc_list)).pack(side="right", padx=(0, 6))

        lf = ttk.LabelFrame(enc, text=" 待加密文件 ", style="Card.TLabelframe", padding=8)
        lf.pack(fill="both", expand=True, pady=(8, 0))
        self.enc_list = self._make_listbox(lf)

        pf = ttk.LabelFrame(enc, text=" 🔑 密码 ", style="Card.TLabelframe", padding=12)
        pf.pack(fill="x", pady=10)
        ttk.Label(pf, text="密码", style="CardMuted.TLabel").grid(
            row=0, column=0, sticky="e", padx=(0, 8), pady=3)
        pwbox = ttk.Frame(pf, style="Card.TFrame")
        pwbox.grid(row=0, column=1, sticky="ew", pady=3)
        self.enc_pw = ttk.Entry(pwbox, show="•")
        self.enc_pw.pack(side="left", fill="x", expand=True)
        self.strength = ttk.Label(pwbox, text="", style="Strength.TLabel",
                                  width=8, anchor="e")
        self.strength.pack(side="left", padx=(8, 0))
        self.enc_pw.bind("<KeyRelease>", lambda e: self._update_strength())

        ttk.Label(pf, text="确认密码", style="CardMuted.TLabel").grid(
            row=1, column=0, sticky="e", padx=(0, 8), pady=3)
        self.enc_pw2 = ttk.Entry(pf, show="•")
        self.enc_pw2.grid(row=1, column=1, sticky="ew", pady=3)

        row1 = ttk.Frame(pf, style="Card.TFrame")
        row1.grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self.show_pw = tk.BooleanVar(value=False)
        ttk.Checkbutton(row1, text="显示密码", style="Card.TCheckbutton",
                        variable=self.show_pw,
                        command=self._toggle_pw).pack(side="left")
        self.hide_name = tk.BooleanVar(value=False)
        ttk.Checkbutton(row1, text="隐藏原文件名（密文随机命名）",
                        style="Card.TCheckbutton",
                        variable=self.hide_name).pack(side="left", padx=(18, 0))
        self.delete_src = tk.BooleanVar(value=False)
        ttk.Checkbutton(pf, text="加密成功后安全删除原文件（覆写后删除，先试解密一次再勾选）",
                        style="Card.TCheckbutton",
                        variable=self.delete_src).grid(row=3, column=0, columnspan=2,
                                                       sticky="w", pady=(4, 0))
        pf.columnconfigure(1, weight=1)

        self.enc_btn = ttk.Button(enc, text="开始加密", style="Primary.TButton",
                                  command=self._start_encrypt)
        self.enc_btn.pack(pady=(2, 8))
        for w in (self.enc_pw, self.enc_pw2):
            w.bind("<Return>", lambda e: self._start_encrypt())

        # ===== 解密页 =====
        dec = ttk.Frame(nb, padding=(4, 10))
        nb.add(dec, text="  🔓  解密 / 查看  ")

        bar2 = ttk.Frame(dec)
        bar2.pack(fill="x")
        ttk.Button(bar2, text="＋ 选择加密文件 (.svenc)",
                   command=self._dec_add_files).pack(side="left")
        ttk.Button(bar2, text="📂 选择文件夹",
                   command=self._dec_add_folder).pack(side="left", padx=(6, 0))
        ttk.Button(bar2, text="移除选中",
                   command=lambda: self._remove_selected(self.dec_list)).pack(side="right")
        ttk.Button(bar2, text="清空列表",
                   command=lambda: self._clear_list(self.dec_list)).pack(side="right", padx=(0, 6))

        lf2 = ttk.LabelFrame(dec, text=" 待解密文件 ", style="Card.TLabelframe", padding=8)
        lf2.pack(fill="both", expand=True, pady=(8, 0))
        self.dec_list = self._make_listbox(lf2)

        pf2 = ttk.LabelFrame(dec, text=" 🔑 密码 ", style="Card.TLabelframe", padding=12)
        pf2.pack(fill="x", pady=10)
        ttk.Label(pf2, text="密码", style="CardMuted.TLabel").grid(
            row=0, column=0, sticky="e", padx=(0, 8), pady=3)
        self.dec_pw = ttk.Entry(pf2, show="•")
        self.dec_pw.grid(row=0, column=1, sticky="ew", pady=3)
        pf2.columnconfigure(1, weight=1)
        ttk.Label(pf2, text="密码错误时会立即停止，不会解出任何内容",
                  style="CardFaint.TLabel").grid(
            row=1, column=1, sticky="w", pady=(4, 0))
        self.dec_pw.bind("<Return>", lambda e: self._start_decrypt())

        btnrow = ttk.Frame(dec)
        btnrow.pack(pady=(2, 8))
        self.dec_btn = ttk.Button(btnrow, text="解密到原位置", style="Primary.TButton",
                                  command=self._start_decrypt)
        self.dec_btn.pack(side="left", padx=(0, 10))
        self.preview_btn = ttk.Button(btnrow, text="👁 解密并预览（用完彻底清理）",
                                      style="View.TButton", command=self._start_preview)
        self.preview_btn.pack(side="left")

        # ===== 底部：进度 + 状态 + 日志 =====
        prog = ttk.Frame(self, padding=(14, 0))
        prog.pack(fill="x")
        self.pbar = ttk.Progressbar(prog, style="SV.Horizontal.TProgressbar", maximum=1000)
        self.pbar.pack(side="left", fill="x", expand=True)
        self.cancel_btn = ttk.Button(prog, text="取消", style="Danger.TButton",
                                     command=self._cancel, state="disabled")
        self.cancel_btn.pack(side="left", padx=(10, 0))

        self.status = ttk.Label(self, text="就绪 — 添加文件后输入密码即可开始（提示：列表支持右键菜单）",
                                style="Status.TLabel", anchor="w", padding=(16, 4))
        self.status.pack(fill="x")

        lf3 = ttk.LabelFrame(self, text=" 处理日志 ", style="Card.TLabelframe",
                             padding=6)
        lf3.pack(fill="both", padx=14, pady=(2, 4))
        self.log = tk.Text(lf3, height=7, state="disabled", wrap="none",
                           bg=LOG_BG, fg="#B9C2D4", font=FONT_LOG, relief="flat",
                           insertbackground=TEXT, selectbackground="#33415F",
                           highlightthickness=1, highlightbackground=BORDER_S,
                           highlightcolor=ACCENT, padx=8, pady=6)
        sb3 = ttk.Scrollbar(lf3, orient="vertical", command=self.log.yview)
        self.log.config(yscrollcommand=sb3.set)
        self.log.pack(side="left", fill="both", expand=True)
        sb3.pack(side="right", fill="y")
        for tag, color in (("ok", GREEN), ("err", RED), ("warn", AMBER),
                           ("dim", FAINT), ("info", "#B9C2D4"), ("acc", ACCENT)):
            self.log.tag_configure(tag, foreground=color)

        ttk.Label(self, text="⚠ 密码一旦遗忘将无法找回 · 请牢记密码　|　密文可随意复制、移动、上传网盘",
                  background=BG, foreground=FAINT, font=FONT_XS).pack(
            fill="x", padx=16, pady=(0, 8))

    def _make_listbox(self, parent) -> tk.Listbox:
        box = tk.Listbox(parent, selectmode="extended", activestyle="none",
                         bg=LIST_BG, fg="#C7CCDA", font=FONT, relief="flat",
                         selectbackground="#35507F", selectforeground="white",
                         highlightthickness=1, highlightbackground=BORDER_S,
                         highlightcolor=ACCENT, borderwidth=0)
        sb = ttk.Scrollbar(parent, orient="vertical", command=box.yview)
        box.config(yscrollcommand=sb.set)
        box.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self._show_placeholder(box)
        self._bind_menu(box)
        return box

    def _bind_menu(self, box: tk.Listbox) -> None:
        m = tk.Menu(box, tearoff=0, bg=CARD, fg=TEXT, relief="flat",
                    activebackground=FIELD_HV, activeforeground="white",
                    bd=0, font=FONT_SM)
        m.add_command(label="📂 打开所在文件夹", command=lambda: self._open_location(box))
        m.add_separator()
        m.add_command(label="移除选中", command=lambda: self._remove_selected(box))
        m.add_command(label="清空列表", command=lambda: self._clear_list(box))

        def popup(e):
            if box.size() and box.get(0) == PLACEHOLDER and box.size() == 1:
                return
            try:
                m.tk_popup(e.x_root, e.y_root)
            finally:
                m.grab_release()

        box.bind("<Button-3>", popup)
        box.bind("<Button-2>", popup)  # 部分鼠标中键

    def _open_location(self, box: tk.Listbox) -> None:
        sel = box.curselection()
        target = box.get(sel[0]) if sel else (box.get(0) if box.size() else "")
        if not target or target == PLACEHOLDER:
            return
        try:
            os.startfile(str(Path(target).parent))  # noqa: Windows only
        except OSError:
            pass

    def _show_placeholder(self, box: tk.Listbox) -> None:
        if box.size() == 0:
            box.insert("end", PLACEHOLDER)
            box.itemconfig("end", foreground=FAINT)

    # ----- 小工具 ---------------------------------------------------------

    def _list_paths(self, box: tk.Listbox) -> list[Path]:
        return [Path(box.get(i)) for i in range(box.size())
                if box.get(i) != PLACEHOLDER]

    def _add_paths(self, box: tk.Listbox, paths) -> None:
        if box.size() == 1 and box.get(0) == PLACEHOLDER:
            box.delete(0)
        existing = set(self._list_paths(box))
        for p in paths:
            if p not in existing:
                box.insert("end", str(p))
                existing.add(p)
        real = self._list_paths(box)
        if real:
            total = 0
            for p in real:
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
            self._set_status(f"已添加 {len(real)} 个文件 · 共 {total / 1048576:.1f} MB")

    def _remove_selected(self, box: tk.Listbox) -> None:
        for i in sorted(box.curselection(), reverse=True):
            box.delete(i)
        self._show_placeholder(box)

    def _clear_list(self, box: tk.Listbox) -> None:
        box.delete(0, "end")
        self._show_placeholder(box)

    def _log(self, line: str, tag: str = "info"):
        self.log.config(state="normal")
        self.log.insert("end", line + "\n", tag)
        self.log.see("end")
        self.log.config(state="disabled")

    def _toggle_pw(self):
        ch = "" if self.show_pw.get() else "•"
        self.enc_pw.config(show=ch)
        self.enc_pw2.config(show=ch)

    def _update_strength(self):
        pw = self.enc_pw.get()
        if not pw:
            self.strength.config(text="")
            return
        classes = sum((any(c.islower() for c in pw), any(c.isupper() for c in pw),
                       any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw)))
        if len(pw) >= 10 and classes >= 3:
            text, color = "强度：强", GREEN
        elif len(pw) >= 8 and classes >= 2:
            text, color = "强度：中", AMBER
        else:
            text, color = "强度：弱", RED
        self.strength.config(text=text, foreground=color)

    def _enc_add_files(self) -> None:
        files = filedialog.askopenfilenames(
            parent=self, title="选择要加密的图片 / 视频 / 文件",
            filetypes=[("常用媒体", "*.jpg *.jpeg *.png *.gif *.bmp *.webp *.heic *.avif *.mp4 *.mkv *.avi *.mov *.wmv *.flv *.webm *.m4v *.ts *.mpg *.mpeg *.3gp *.rmvb"),
                       ("所有文件", "*.*")])
        self._add_paths(self.enc_list, [Path(f) for f in files])

    def _enc_add_folder(self) -> None:
        d = filedialog.askdirectory(parent=self, title="选择文件夹（递归添加其中的图片/视频）")
        if not d:
            return
        root = Path(d)
        found = [p for p in root.rglob("*")
                 if p.is_file() and p.suffix.lower() in MEDIA_EXTS]
        found.sort()
        if not found:
            messagebox.showinfo(APP_NAME, "该文件夹（含子文件夹）中没有找到图片/视频文件。", parent=self)
            return
        self._add_paths(self.enc_list, found)

    def _dec_add_files(self) -> None:
        files = filedialog.askopenfilenames(
            parent=self, title="选择 .svenc 加密文件",
            filetypes=[("加密文件", "*.svenc"), ("所有文件", "*.*")])
        self._add_paths(self.dec_list, [Path(f) for f in files])

    def _dec_add_folder(self) -> None:
        d = filedialog.askdirectory(parent=self, title="选择文件夹（递归添加其中的 .svenc）")
        if not d:
            return
        found = sorted(p for p in Path(d).rglob("*" + EXT) if p.is_file())
        if not found:
            messagebox.showinfo(APP_NAME, "该文件夹中没有找到 .svenc 加密文件。", parent=self)
            return
        self._add_paths(self.dec_list, found)

    # ----- 任务调度 -------------------------------------------------------

    def _set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self.enc_btn.config(state=state)
        self.dec_btn.config(state=state)
        self.preview_btn.config(state=state)
        self.cancel_btn.config(state="normal" if busy else "disabled")
        if not busy:
            self.pbar["value"] = 0

    def _set_status(self, text: str, color: str = MUTED) -> None:
        self.status.config(text=text, foreground=color)

    def _validate(self, files: list[Path], pw: str, pw2: str | None) -> bool:
        if not files:
            messagebox.showwarning(APP_NAME, "请先添加文件。", parent=self)
            return False
        if not pw:
            messagebox.showwarning(APP_NAME, "请输入密码。", parent=self)
            return False
        if len(pw) < 6:
            if not messagebox.askyesno(APP_NAME, "密码太短（建议至少 8 位）。\n确定要继续吗？", parent=self):
                return False
        if pw2 is not None and pw != pw2:
            messagebox.showwarning(APP_NAME, "两次输入的密码不一致。", parent=self)
            return False
        return True

    def _start_encrypt(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        files = self._list_paths(self.enc_list)
        pw, pw2 = self.enc_pw.get(), self.enc_pw2.get()
        if not self._validate(files, pw, pw2):
            return
        for f in files:
            if f.suffix.lower() == EXT:
                messagebox.showwarning(APP_NAME, f"{f.name} 已经是加密文件，请从列表移除。", parent=self)
                return
        self._launch("enc", files, pw,
                     delete_after=self.delete_src.get(),
                     hide_name=self.hide_name.get())

    def _start_decrypt(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        files = self._list_paths(self.dec_list)
        pw = self.dec_pw.get()
        if not self._validate(files, pw, None):
            return
        self._launch("dec", files, pw)

    def _start_preview(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        files = self._list_paths(self.dec_list)
        pw = self.dec_pw.get()
        if not self._validate(files, pw, None):
            return
        self._cleanup_preview(silent=True)
        self.preview_dir = Path(tempfile.mkdtemp(prefix="svview_"))
        self._launch("view", files, pw, view_dir=self.preview_dir)

    def _launch(self, mode: str, files: list[Path], pw: str,
                delete_after: bool = False, hide_name: bool = False,
                view_dir: Path | None = None) -> None:
        self.cancel_ev.clear()
        while not self.q.empty():
            try:
                self.q.get_nowait()
            except queue.Empty:
                break
        total = 0
        for f in files:
            try:
                total += f.stat().st_size
            except OSError:
                pass
        self.total_bytes = max(1, total)
        self._cur_mode = mode
        self._cur_file = ""
        self._pct = 0.0
        self._set_busy(True)
        self.style.configure("SV.Horizontal.TProgressbar", background=ACCENT)
        self._log(f"── 开始{VERBS[mode]}：{len(files)} 个文件 · "
                  f"{self.total_bytes / 1048576:.1f} MB ──", "dim")
        self._set_status("正在派生密钥……", ACCENT)
        self.worker = threading.Thread(target=self._work,
                                       args=(mode, files, pw, delete_after,
                                             hide_name, view_dir),
                                       daemon=True)
        self.worker.start()
        self.after(80, self._poll)

    def _cancel(self) -> None:
        self.cancel_ev.set()
        self._set_status("正在取消……", AMBER)

    # ----- 预览（临时解密）管理 -------------------------------------------

    def _show_preview_win(self) -> None:
        if self.preview_win is not None:
            try:
                self.preview_win.destroy()
            except tk.TclError:
                pass
        w = tk.Toplevel(self)
        self.preview_win = w
        w.title("预览 — 临时解密文件")
        w.configure(bg=CARD)
        w.geometry("560x340")
        w.transient(self)
        frm = ttk.Frame(w, style="Card.TFrame", padding=16)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="以下临时文件已用系统默认程序打开：",
                  style="CardMuted.TLabel").pack(anchor="w")
        lb = tk.Listbox(frm, bg=LIST_BG, fg="#C7CCDA", font=FONT_SM, relief="flat",
                        activestyle="none", selectbackground="#35507F",
                        highlightthickness=1, highlightbackground=BORDER_S)
        lb.pack(fill="both", expand=True, pady=8)
        for p in self.preview_files:
            lb.insert("end", p.name)
        ttk.Label(frm, text="文件位于系统临时目录，看完点击下方按钮彻底清除；"
                            "直接关闭软件时也会自动清理。",
                  style="CardFaint.TLabel", wraplength=500,
                  justify="left").pack(anchor="w", pady=(0, 10))
        ttk.Button(frm, text="🧹 彻底清理临时文件", style="Danger.TButton",
                   command=self._cleanup_preview).pack()

    def _cleanup_preview(self, silent: bool = False) -> None:
        remaining = []
        for p in self.preview_files:
            try:
                if p.exists() and not secure_delete(p):
                    remaining.append(p)
            except OSError:
                remaining.append(p)
        if self.preview_dir is not None:
            try:
                os.rmdir(self.preview_dir)
            except OSError:
                pass
        self.preview_dir = None
        self.preview_files = remaining
        if self.preview_win is not None:
            try:
                self.preview_win.destroy()
            except tk.TclError:
                pass
            self.preview_win = None
        if not silent:
            if remaining:
                self._log(f"[清理] {len(remaining)} 个临时文件被程序占用，"
                          f"请关闭看图/播放器后重试", "warn")
                self._set_status("部分临时文件被占用", AMBER)
            else:
                self._log("[清理] 预览临时文件已彻底清除", "ok")
                self._set_status("预览临时文件已清理", GREEN)

    def _on_close(self) -> None:
        try:
            self._cleanup_preview(silent=True)
        finally:
            self.destroy()

    # ----- 后台线程 -------------------------------------------------------

    def _work(self, mode: str, files: list[Path], pw: str,
              delete_after: bool, hide_name: bool, view_dir: Path | None) -> None:
        q = self.q
        state = {"bytes": 0}

        def report(n: int) -> None:
            state["bytes"] += n
            q.put(("prog", state["bytes"]))

        def log(msg: str, tag: str = "info") -> None:
            q.put(("log", (msg, tag)))

        ok = fail = 0
        outs: list[Path] = []
        salt = os.urandom(SALT_LEN)
        key: bytes | None = None
        aborted = False
        try:
            for f in files:
                q.put(("file", f.name))
                if self.cancel_ev.is_set():
                    log(f"[跳过] {f.name}（已取消）", "dim")
                    continue
                try:
                    if mode == "enc":
                        if key is None:
                            key = derive_key(pw, salt)
                        base = f"SV-{os.urandom(4).hex().upper()}" if hide_name else f.name
                        dst = unique_path(f.parent, base + EXT)
                        encrypt_file(f, dst, key, salt, report, self.cancel_ev)
                        ok += 1
                        self.last_out_dir = str(f.parent)
                        log(f"[成功] {f.name}  →  {dst.name}", "ok")
                        if delete_after:
                            if secure_delete(f):
                                log(f"[安全删除] 已覆写并删除原文件 {f.name}", "warn")
                            else:
                                log(f"[警告] 原文件删除失败（可能被占用）{f.name}", "warn")
                    elif mode == "dec":
                        out = decrypt_file(f, f.parent, pw, report, self.cancel_ev)
                        ok += 1
                        self.last_out_dir = str(f.parent)
                        log(f"[成功] {f.name}  →  {out.name}", "ok")
                    else:  # view
                        out = decrypt_file(f, view_dir, pw, report, self.cancel_ev)
                        ok += 1
                        outs.append(out)
                        log(f"[预览就绪] {f.name}", "ok")
                except PasswordError:
                    fail += 1
                    log(f"[失败] {f.name}: 密码错误", "err")
                    time.sleep(1.0)  # 轻微延迟，增加暴力尝试成本
                    q.put(("abort", "密码错误，已停止。\n\n密码在密码学上无法找回，请核对后重试。"))
                    aborted = True
                    break
                except Cancelled:
                    log(f"[取消] {f.name}", "dim")
                except VaultError as e:
                    fail += 1
                    log(f"[失败] {e}", "err")
                except OSError as e:
                    fail += 1
                    log(f"[失败] {f.name}: {e}", "err")
        finally:
            if mode == "view":
                q.put(("files", outs))
            q.put(("done", (ok, fail, aborted)))

    def _poll(self) -> None:
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "prog":
                    frac = min(1.0, val / self.total_bytes)
                    self._pct = frac
                    self.pbar["value"] = frac * 1000
                    self._status_progress()
                elif kind == "file":
                    self._cur_file = val
                    self._status_progress()
                elif kind == "log":
                    msg, tag = val
                    self._log(msg, tag)
                elif kind == "files":
                    self.preview_files = [Path(p) for p in val]
                elif kind == "abort":
                    self._pending_error = val
                elif kind == "done":
                    self._finish(*val)
                    return
        except queue.Empty:
            pass
        if self.worker and self.worker.is_alive():
            self.after(80, self._poll)
        else:
            self._finish(0, 0, False)

    def _status_progress(self) -> None:
        verb = VERBS.get(self._cur_mode, "处理")
        name = self._cur_file
        if len(name) > 30:
            name = name[:28] + "…"
        txt = f"{verb} {name} …… {self._pct * 100:.1f}%" if name else \
              f"处理中…… {self._pct * 100:.1f}%"
        self._set_status(txt, ACCENT)

    def _finish(self, ok: int, fail: int, aborted: bool) -> None:
        self._set_busy(False)

        if self._cur_mode == "view":
            if aborted or self.cancel_ev.is_set() or not self.preview_files:
                self._cleanup_preview(silent=True)
                if aborted:
                    self.style.configure("SV.Horizontal.TProgressbar", background=RED)
                    self._set_status("预览已停止：密码错误", RED)
                    self._log("── 预览已停止：密码错误 ──", "err")
                else:
                    self._set_status("预览未完成", AMBER)
            else:
                self.style.configure("SV.Horizontal.TProgressbar", background=GREEN)
                opened = 0
                for p in self.preview_files[:8]:
                    try:
                        os.startfile(p)  # noqa: Windows only
                        opened += 1
                    except OSError:
                        pass
                if len(self.preview_files) > 8:
                    self._log(f"[提示] 其余 {len(self.preview_files) - 8} 个文件"
                              f"在临时目录中，未自动打开", "dim")
                self._log(f"—— 预览：解密 {ok} 个，已打开 {opened} 个 ——", "ok")
                self._set_status(f"预览已打开（{opened} 个），看完请及时清理", GREEN)
                self._show_preview_win()
            if self._pending_error:
                messagebox.showerror(APP_NAME, self._pending_error, parent=self)
                self._pending_error = None
            self.after(1500, lambda: self.style.configure(
                "SV.Horizontal.TProgressbar", background=ACCENT))
            return

        if aborted:
            self.style.configure("SV.Horizontal.TProgressbar", background=RED)
            self._set_status("已停止：密码错误", RED)
            self._log("── 已停止：密码错误 ──", "err")
        elif self.cancel_ev.is_set():
            self._set_status(f"已取消（成功 {ok} 个，失败/跳过 {fail} 个）", AMBER)
            self._log(f"── 已取消：成功 {ok} 个 ──", "warn")
        else:
            self.style.configure("SV.Horizontal.TProgressbar", background=GREEN)
            self._set_status(f"完成：成功 {ok} 个，失败 {fail} 个", GREEN)
            self._log(f"── 完成：成功 {ok} 个 · 失败 {fail} 个 ──", "ok")
        if self._pending_error:
            messagebox.showerror(APP_NAME, self._pending_error, parent=self)
            self._pending_error = None
        elif ok > 0 and self.last_out_dir and not aborted:
            if messagebox.askyesno(APP_NAME, f"处理完成（成功 {ok} 个）。\n是否打开输出文件夹查看？",
                                   parent=self):
                try:
                    os.startfile(self.last_out_dir)  # noqa: Windows only
                except OSError:
                    pass
        self.after(1500, lambda: self.style.configure(
            "SV.Horizontal.TProgressbar", background=ACCENT))


def main() -> int:
    if sys.platform == "win32":
        try:  # 高 DPI 下界面更清晰
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    if not HAVE_CRYPTO:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            APP_NAME,
            "缺少加密库 cryptography。\n\n请先在命令行运行：\n"
            "    python -m pip install cryptography\n\n然后重新启动本程序。")
        return 1
    if "--selftest" in sys.argv:
        return selftest()
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
