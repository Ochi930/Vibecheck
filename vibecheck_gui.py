#!/usr/bin/env python3
"""vibecheck GUI - paste a URL, press Enter, read the results.
Keep this file in the same folder as vibecheck.py."""
import threading
import tkinter as tk
from tkinter import scrolledtext

import vibecheck


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("vibecheck - is this site vibe coded?")
        self.geometry("820x640")
        self.minsize(600, 400)

        top = tk.Frame(self, padx=12, pady=12)
        top.pack(fill="x")
        tk.Label(top, text="Website URL:", font=("Segoe UI", 10)).pack(side="left")
        self.url = tk.StringVar()
        self.entry = tk.Entry(top, textvariable=self.url, font=("Segoe UI", 11))
        self.entry.pack(side="left", fill="x", expand=True, padx=8)
        self.entry.bind("<Return>", lambda e: self.run())
        self.entry.focus()
        self.btn = tk.Button(top, text="Analyze", width=10, command=self.run)
        self.btn.pack(side="left")

        self.score = tk.Label(self, text="", font=("Segoe UI", 16, "bold"), anchor="w", padx=14)
        self.score.pack(fill="x")

        self.out = scrolledtext.ScrolledText(self, wrap="word", font=("Consolas", 10), padx=10, pady=8)
        self.out.pack(fill="both", expand=True, padx=12, pady=(4, 8))
        self.out.tag_config("head", font=("Consolas", 10, "bold"))
        self.out.tag_config("fix", foreground="#1a7f37")
        self.out.tag_config("ev", foreground="#777777")

        bottom = tk.Frame(self, padx=12, pady=(0))
        bottom.pack(fill="x", pady=(0, 10))
        tk.Button(bottom, text="Copy report", command=self.copy).pack(side="left")
        self.status = tk.Label(bottom, text="Paste a URL and press Enter.", fg="#555")
        self.status.pack(side="left", padx=10)

    def run(self):
        u = self.url.get().strip()
        if not u:
            return
        if not u.startswith("http"):
            u = "https://" + u
        self.btn.config(state="disabled")
        self.status.config(text="Analyzing %s ..." % u)
        self.score.config(text="", fg="black")
        self.out.delete("1.0", "end")
        threading.Thread(target=self.work, args=(u,), daemon=True).start()

    def work(self, u):
        try:
            html, hdr, _ = vibecheck.fetch(u)
            if html is None:
                self.after(0, self.fail, "Could not fetch " + u)
                return
            r = vibecheck.analyse(u, html, hdr)
            self.after(0, self.show, r)
        except Exception as e:
            self.after(0, self.fail, str(e))

    def fail(self, msg):
        self.btn.config(state="normal")
        self.status.config(text=msg)

    def show(self, r):
        self.btn.config(state="normal")
        self.status.config(text="Done.")
        s = r["score"]
        color = "#cf222e" if s >= 60 else "#d97706" if s >= 40 else "#9a6700" if s >= 20 else "#1a7f37"
        self.score.config(text="%d/100  -  %s" % (s, r["verdict"]), fg=color)
        if not r["findings"]:
            self.out.insert("end", "No red flags found.")
        for f in r["findings"]:
            self.out.insert("end", "[%s | +%d] %s\n" % (f["category"], f["weight"], f["reason"]), "head")
            if f["evidence"]:
                self.out.insert("end", "   evidence: %s\n" % f["evidence"], "ev")
            self.out.insert("end", "   fix: %s\n\n" % f["fix"], "fix")

    def copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.score.cget("text") + "\n\n" + self.out.get("1.0", "end"))
        self.status.config(text="Report copied to clipboard.")


if __name__ == "__main__":
    App().mainloop()
