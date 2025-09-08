# app_auth.py
import tkinter as tk
from tkinter import messagebox
import json
import os
import hashlib
import binascii

USERS_FILE = "users.json"

# --- Helpers for password hashing ---
def hash_password(password: str, salt: bytes = None):
    """Trả về (salt_bytes, hash_bytes). Nếu salt=None thì tạo salt mới."""
    if salt is None:
        salt = os.urandom(16)
    # PBKDF2-HMAC-SHA256, 100000 vòng
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return salt, dk

def save_user(username: str, password: str):
    users = load_users()
    if username in users:
        return False, "Tài khoản đã tồn tại."
    salt, dk = hash_password(password)
    users[username] = {
        "salt": binascii.hexlify(salt).decode("ascii"),
        "hash": binascii.hexlify(dk).decode("ascii")
    }
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)
    return True, "Đăng ký thành công."

def verify_user(username: str, password: str):
    users = load_users()
    if username not in users:
        return False, "Tài khoản không tồn tại."
    stored = users[username]
    salt = binascii.unhexlify(stored["salt"])
    stored_hash = stored["hash"]
    _, dk = hash_password(password, salt)
    if binascii.hexlify(dk).decode("ascii") == stored_hash:
        return True, "Đăng nhập thành công."
    else:
        return False, "Mật khẩu không đúng."

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

# --- GUI App ---
class AuthApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Đăng nhập / Đăng ký")
        self.geometry("360x220")
        self.resizable(False, False)

        # Frames
        self.frame_main = tk.Frame(self)
        self.frame_login = tk.Frame(self)
        self.frame_register = tk.Frame(self)

        self.create_main()
        self.create_login()
        self.create_register()

        self.frame_main.pack(fill="both", expand=True)

    def create_main(self):
        f = self.frame_main
        tk.Label(f, text="Chọn hành động", font=("Arial", 14)).pack(pady=12)
        tk.Button(f, text="Đăng nhập", width=20, command=self.show_login).pack(pady=6)
        tk.Button(f, text="Đăng ký", width=20, command=self.show_register).pack(pady=6)
        tk.Button(f, text="Thoát", width=20, command=self.quit).pack(pady=6)

    def create_login(self):
        f = self.frame_login
        tk.Label(f, text="ĐĂNG NHẬP", font=("Arial", 14)).pack(pady=8)
        tk.Label(f, text="Tên đăng nhập").pack(anchor="w", padx=20)
        self.login_user = tk.Entry(f)
        self.login_user.pack(fill="x", padx=20)
        tk.Label(f, text="Mật khẩu").pack(anchor="w", padx=20, pady=(8,0))
        self.login_pass = tk.Entry(f, show="*")
        self.login_pass.pack(fill="x", padx=20)
        btn_frame = tk.Frame(f)
        btn_frame.pack(pady=12)
        tk.Button(btn_frame, text="Đăng nhập", command=self.do_login, width=12).grid(row=0, column=0, padx=6)
        tk.Button(btn_frame, text="Quay lại", command=self.show_main, width=12).grid(row=0, column=1, padx=6)

    def create_register(self):
        f = self.frame_register
        tk.Label(f, text="ĐĂNG KÝ", font=("Arial", 14)).pack(pady=8)
        tk.Label(f, text="Tên đăng nhập").pack(anchor="w", padx=20)
        self.reg_user = tk.Entry(f)
        self.reg_user.pack(fill="x", padx=20)
        tk.Label(f, text="Mật khẩu").pack(anchor="w", padx=20, pady=(8,0))
        self.reg_pass = tk.Entry(f, show="*")
        self.reg_pass.pack(fill="x", padx=20)
        tk.Label(f, text="Nhập lại mật khẩu").pack(anchor="w", padx=20, pady=(8,0))
        self.reg_pass2 = tk.Entry(f, show="*")
        self.reg_pass2.pack(fill="x", padx=20)
        btn_frame = tk.Frame(f)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Đăng ký", command=self.do_register, width=12).grid(row=0, column=0, padx=6)
        tk.Button(btn_frame, text="Quay lại", command=self.show_main, width=12).grid(row=0, column=1, padx=6)

    def clear_entries(self):
        for e in [self.login_user, self.login_pass, self.reg_user, self.reg_pass, self.reg_pass2]:
            try:
                e.delete(0, tk.END)
            except Exception:
                pass

    def show_main(self):
        self.frame_login.pack_forget()
        self.frame_register.pack_forget()
        self.clear_entries()
        self.frame_main.pack(fill="both", expand=True)

    def show_login(self):
        self.frame_main.pack_forget()
        self.frame_register.pack_forget()
        self.clear_entries()
        self.frame_login.pack(fill="both", expand=True)

    def show_register(self):
        self.frame_main.pack_forget()
        self.frame_login.pack_forget()
        self.clear_entries()
        self.frame_register.pack(fill="both", expand=True)

    def do_register(self):
        username = self.reg_user.get().strip()
        p1 = self.reg_pass.get()
        p2 = self.reg_pass2.get()
        if not username or not p1:
            messagebox.showwarning("Lỗi", "Điền đầy đủ tên đăng nhập và mật khẩu.")
            return
        if p1 != p2:
            messagebox.showwarning("Lỗi", "Mật khẩu không khớp.")
            return
        ok, msg = save_user(username, p1)
        if ok:
            messagebox.showinfo("Thành công", msg)
            self.show_login()
        else:
            messagebox.showwarning("Lỗi", msg)

    def do_login(self):
        username = self.login_user.get().strip()
        password = self.login_pass.get()
        if not username or not password:
            messagebox.showwarning("Lỗi", "Điền đầy đủ tên đăng nhập và mật khẩu.")
            return
        ok, msg = verify_user(username, password)
        if ok:
            messagebox.showinfo("Chào bạn", f"{msg} — {username}")
            # tùy biến sau đăng nhập (mở cửa sổ mới...)
        else:
            messagebox.showerror("Lỗi", msg)

if __name__ == "__main__":
    app = AuthApp()
    app.mainloop()
