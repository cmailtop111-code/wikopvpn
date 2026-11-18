import json
import os
import queue
import threading
import tkinter as tk
from tkinter import messagebox

import core

BG = "#FFFFFF"
ACCENT = "#4A86C5"
ACCENT_DARK = "#3A6FA8"
SOFT = "#EAF2FB"
TEXT = "#24364B"
MUTED = "#7A8CA3"
SETTINGS = os.path.join(core.DATA_DIR, "settings.json")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WikopVPN")
        self.geometry("400x660")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.servers = []
        self.vpn = core.Vpn()
        self.q = queue.Queue()
        self._build()
        self._load_settings()
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(200, self._poll)
        self.after(1000, self._watch)

    def _build(self):
        try:
            img = tk.PhotoImage(file=core.resource_path("logo.png")).subsample(5, 5)
            self.logo = img
            tk.Label(self, image=img, bg=BG).pack(pady=(18, 0))
        except tk.TclError:
            pass
        tk.Label(self, text="WikopVPN", font=("Segoe UI", 20, "bold"), fg=TEXT, bg=BG).pack()
        tk.Label(self, text="Безопасно. Быстро. Свободно.", font=("Segoe UI", 10),
                 fg=MUTED, bg=BG).pack(pady=(0, 14))

        box = tk.Frame(self, bg=SOFT, padx=12, pady=10)
        box.pack(fill="x", padx=20)
        tk.Label(box, text="Ссылка на подписку", font=("Segoe UI", 9), fg=MUTED, bg=SOFT).pack(anchor="w")
        self.url = tk.Entry(box, font=("Segoe UI", 10), relief="flat", bg="white", fg=TEXT,
                            highlightthickness=1, highlightbackground="#D3E2F2", highlightcolor=ACCENT)
        self.url.pack(fill="x", ipady=6, pady=(4, 8))
        self.upd = self._button(box, "Обновить подписку", self._update, soft=True)
        self.upd.pack(fill="x")

        tk.Label(self, text="Серверы", font=("Segoe UI", 10, "bold"), fg=TEXT, bg=BG).pack(anchor="w", padx=22, pady=(14, 4))
        self.lb = tk.Listbox(self, font=("Segoe UI", 11), relief="flat", bg=BG, fg=TEXT,
                             selectbackground=SOFT, selectforeground=ACCENT_DARK, activestyle="none",
                             highlightthickness=1, highlightbackground="#D3E2F2", exportselection=False, height=10)
        self.lb.pack(fill="x", padx=20)

        self.btn = self._button(self, "Подключиться", self._toggle)
        self.btn.pack(fill="x", padx=20, pady=(16, 6), ipady=6)
        self.status = tk.Label(self, text="Не подключено", font=("Segoe UI", 10), fg=MUTED, bg=BG)
        self.status.pack()

    def _button(self, parent, text, cmd, soft=False):
        bg, fg, hover = (("white", ACCENT, SOFT) if soft else (ACCENT, "white", ACCENT_DARK))
        b = tk.Button(parent, text=text, command=cmd, font=("Segoe UI", 11, "bold"), relief="flat",
                      bg=bg, fg=fg, activebackground=hover, activeforeground=fg, cursor="hand2", bd=0)
        b.bind("<Enter>", lambda e: b.config(bg=hover))
        b.bind("<Leave>", lambda e: b.config(bg=bg))
        return b

    def _load_settings(self):
        try:
            with open(SETTINGS, encoding="utf-8") as f:
                s = json.load(f)
            self.url.insert(0, s.get("url", ""))
            self.servers = s.get("servers", [])
            self._fill()
        except (OSError, ValueError):
            pass

    def _save_settings(self):
        os.makedirs(core.DATA_DIR, exist_ok=True)
        with open(SETTINGS, "w", encoding="utf-8") as f:
            json.dump({"url": self.url.get().strip(), "servers": self.servers}, f, ensure_ascii=False)

    def _fill(self):
        self.lb.delete(0, "end")
        for s in self.servers:
            self.lb.insert("end", "  " + s["name"])
        if self.servers:
            self.lb.selection_set(0)

    def _update(self):
        url = self.url.get().strip()
        if not core.is_allowed_url(url):
            messagebox.showerror("WikopVPN", "Подписка должна быть с https://wikopvpn.site.\nДругие сайты не принимаются.")
            return
        self.upd.config(state="disabled", text="Загрузка...")

        def work():
            try:
                self.q.put(("ok", core.fetch_subscription(url)))
            except Exception as e:
                self.q.put(("err", str(e)))
        threading.Thread(target=work, daemon=True).start()

    def _poll(self):
        try:
            while True:
                kind, data = self.q.get_nowait()
                self.upd.config(state="normal", text="Обновить подписку")
                if kind == "ok":
                    self.servers = data
                    self._fill()
                    self._save_settings()
                else:
                    messagebox.showerror("WikopVPN", data)
        except queue.Empty:
            pass
        self.after(200, self._poll)

    def _watch(self):
        if self.btn["text"] == "Отключиться" and not self.vpn.running:
            self.vpn.disconnect()
            self._set_state(False)
            messagebox.showwarning("WikopVPN", f"Соединение прервано. Лог: {self.vpn.log_path}")
        self.after(1000, self._watch)

    def _set_state(self, on, name=""):
        self.btn.config(text="Отключиться" if on else "Подключиться")
        self.status.config(text=f"Подключено: {name}" if on else "Не подключено", fg=ACCENT if on else MUTED)

    def _toggle(self):
        if self.vpn.running:
            self.vpn.disconnect()
            self._set_state(False)
            return
        sel = self.lb.curselection()
        if not self.servers or not sel:
            messagebox.showinfo("WikopVPN", "Сначала загрузи подписку и выбери сервер.")
            return
        s = self.servers[sel[0]]
        try:
            self.vpn.connect(s)
            self._set_state(True, s["name"])
        except Exception as e:
            self.vpn.disconnect()
            messagebox.showerror("WikopVPN", str(e))

    def _close(self):
        self.vpn.disconnect()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
