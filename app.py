import hashlib
import json
import secrets
import sqlite3
import tkinter as tk
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


LOCAL_DB_FILE = Path("lab3.db")


def hash_password(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 120_000).hex()


def _insert_user_compat(conn: sqlite3.Connection, login: str, password: str) -> None:
    """Insert user for both new and legacy users schemas."""
    cols = {
        row[1]: row
        for row in conn.execute("PRAGMA table_info(users)").fetchall()
    }
    salt = secrets.token_hex(16)
    payload: dict[str, object] = {
        "login": login,
        "password_hash": hash_password(password, salt),
        "salt": salt,
    }
    if "is_active" in cols:
        payload["is_active"] = 1
    if "registered_at" in cols:
        payload["registered_at"] = datetime.now().isoformat(sep=" ", timespec="seconds")

    fields = ", ".join(payload.keys())
    placeholders = ", ".join("?" for _ in payload)
    conn.execute(
        f"INSERT INTO users({fields}) VALUES({placeholders})",
        tuple(payload.values()),
    )


class LoginWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Авторизация")
        self.geometry("460x320")
        self.resizable(False, False)
        self.auth_user: str | None = None

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        login_tab = ttk.Frame(notebook, padding=12)
        register_tab = ttk.Frame(notebook, padding=12)
        notebook.add(login_tab, text="Вход")
        notebook.add(register_tab, text="Регистрация")

        self.login_login = ttk.Entry(login_tab, width=32)
        self.login_password = ttk.Entry(login_tab, width=32, show="*")
        ttk.Label(login_tab, text="Логин").grid(row=0, column=0, sticky="w", pady=6)
        self.login_login.grid(row=0, column=1, pady=6)
        ttk.Label(login_tab, text="Пароль").grid(row=1, column=0, sticky="w", pady=6)
        self.login_password.grid(row=1, column=1, pady=6)
        ttk.Button(login_tab, text="Войти", command=self.try_login).grid(row=2, column=0, columnspan=2, pady=12)
        ttk.Label(login_tab, text="По умолчанию: admin / Admin123!", foreground="#555").grid(
            row=3, column=0, columnspan=2, pady=(8, 0)
        )

        self.reg_login = ttk.Entry(register_tab, width=32)
        self.reg_password = ttk.Entry(register_tab, width=32, show="*")
        self.reg_password2 = ttk.Entry(register_tab, width=32, show="*")
        ttk.Label(register_tab, text="Логин").grid(row=0, column=0, sticky="w", pady=6)
        self.reg_login.grid(row=0, column=1, pady=6)
        ttk.Label(register_tab, text="Пароль").grid(row=1, column=0, sticky="w", pady=6)
        self.reg_password.grid(row=1, column=1, pady=6)
        ttk.Label(register_tab, text="Повтор пароля").grid(row=2, column=0, sticky="w", pady=6)
        self.reg_password2.grid(row=2, column=1, pady=6)
        ttk.Button(register_tab, text="Зарегистрироваться", command=self.try_register).grid(
            row=3, column=0, columnspan=2, pady=12
        )

        self.bind("<Return>", lambda _: self.try_login() if notebook.index("current") == 0 else self.try_register())
        self.login_login.focus_set()

    def try_login(self) -> None:
        login = self.login_login.get().strip()
        password = self.login_password.get()
        if not login or not password:
            messagebox.showerror("Ошибка", "Введите логин и пароль.")
            return

        with sqlite3.connect(LOCAL_DB_FILE) as conn:
            row = conn.execute(
                "SELECT password_hash, salt, is_active FROM users WHERE login = ?",
                (login,),
            ).fetchone()
        if not row:
            messagebox.showerror("Ошибка", "Пользователь не найден.")
            return
        if int(row[2]) != 1:
            messagebox.showerror("Ошибка", "Пользователь деактивирован.")
            return
        if hash_password(password, row[1]) != row[0]:
            messagebox.showerror("Ошибка", "Неверный пароль.")
            return

        self.auth_user = login
        with sqlite3.connect(LOCAL_DB_FILE) as conn:
            conn.execute(
                "INSERT INTO action_logs(user_login, action, entity_type, entity_id, details, created_at) VALUES(?, ?, ?, ?, ?, ?)",
                (login, "LOGIN", "User", 0, "Успешный вход", datetime.now().isoformat(sep=" ", timespec="seconds")),
            )
            conn.commit()
        self.destroy()

    def try_register(self) -> None:
        login = self.reg_login.get().strip()
        p1 = self.reg_password.get()
        p2 = self.reg_password2.get()

        if not login or not p1 or not p2:
            messagebox.showerror("Ошибка", "Заполните все поля.")
            return
        if p1 != p2:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return

        with sqlite3.connect(LOCAL_DB_FILE) as conn:
            exists = conn.execute("SELECT 1 FROM users WHERE login = ?", (login,)).fetchone()
            if exists:
                messagebox.showerror("Ошибка", "Такой логин уже существует.")
                return
            _insert_user_compat(conn, login, p1)
            conn.execute(
                "INSERT INTO action_logs(user_login, action, entity_type, entity_id, details, created_at) VALUES(?, ?, ?, ?, ?, ?)",
                (login, "REGISTER", "User", 0, "Регистрация", datetime.now().isoformat(sep=" ", timespec="seconds")),
            )
            conn.commit()

        self.auth_user = login
        messagebox.showinfo("Успех", "Регистрация выполнена.")
        self.destroy()


class EntityDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk, title: str, fields: list[tuple[str, str]], initial: dict[str, str] | None = None) -> None:
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.result: dict[str, str] | None = None
        initial = initial or {}
        self.entries: dict[str, ttk.Entry] = {}

        frame = ttk.Frame(self, padding=14)
        frame.grid(sticky="nsew")
        for i, (key, label) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky="w", padx=(0, 10), pady=5)
            entry = ttk.Entry(frame, width=38)
            entry.grid(row=i, column=1, sticky="ew", pady=5)
            entry.insert(0, initial.get(key, ""))
            self.entries[key] = entry

        btns = ttk.Frame(frame)
        btns.grid(row=len(fields), column=0, columnspan=2, pady=(12, 0), sticky="e")
        ttk.Button(btns, text="Сохранить", command=self._save).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Отмена", command=self.destroy).pack(side=tk.LEFT, padx=4)
        self.bind("<Return>", lambda _: self._save())
        self.transient(parent)
        self.grab_set()
        self.wait_visibility()
        first = next(iter(self.entries.values()), None)
        if first:
            first.focus_set()
        self.wait_window(self)

    def _save(self) -> None:
        self.result = {k: e.get().strip() for k, e in self.entries.items()}
        self.destroy()


class App(tk.Tk):
    def __init__(self, user_login: str) -> None:
        super().__init__()
        self.user_login = user_login
        self.title(f"Управление курсами ({user_login})")
        self.geometry("1220x760")
        self.minsize(1020, 640)

        self.conn = sqlite3.connect(LOCAL_DB_FILE)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.row_factory = sqlite3.Row
        self.selected_info = tk.StringVar(value="Ничего не выбрано")
        self.node_index: dict[tuple[str, int], str] = {}
        self.drag_item_id: str | None = None

        self._build_styles()
        self._build_ui()
        self.refresh_roots()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Root.TFrame", background="#f1f1f1")
        style.configure("Panel.TLabelframe", background="#f1f1f1", borderwidth=1, relief="solid")
        style.configure("Panel.TLabelframe.Label", background="#f1f1f1")
        style.configure("Header.TLabel", font=("Segoe UI", 31, "bold"), background="#f1f1f1")
        style.configure("RightTitle.TLabel", font=("Segoe UI", 22, "bold"), background="#f1f1f1")
        style.configure("PickedTitle.TLabel", font=("Segoe UI", 15, "bold"), background="#d7d7d7")
        style.configure("PickedInfo.TLabel", font=("Segoe UI", 14), background="#d7d7d7")
        style.configure("Hint.TLabel", font=("Segoe UI", 13), background="#f3efc1")
        style.configure("Action.TButton", font=("Segoe UI", 15), padding=(16, 13))
        style.configure("Treeview", font=("Segoe UI", 13), rowheight=38, background="#fbfbfb")
        style.map("Treeview", background=[("selected", "#bde8f4")], foreground=[("selected", "#111111")])

    def _build_ui(self) -> None:
        root = ttk.Frame(self, style="Root.TFrame", padding=12)
        root.pack(fill=tk.BOTH, expand=True)
        root.rowconfigure(1, weight=1)
        root.columnconfigure(0, weight=1)
        ttk.Label(root, text="Управление курсами", style="Header.TLabel").grid(row=0, column=0, pady=(4, 12))

        content = ttk.Frame(root, style="Root.TFrame")
        content.grid(row=1, column=0, sticky="nsew")
        content.rowconfigure(0, weight=1)
        content.columnconfigure(0, weight=2)
        content.columnconfigure(1, weight=1)

        left = ttk.LabelFrame(content, style="Panel.TLabelframe", padding=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(left, show="tree")
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<<TreeviewOpen>>", self._on_open_node)
        self.tree.bind("<Double-1>", lambda _: self.edit_entity())
        self.tree.bind("<Button-3>", self._show_context_menu)
        self.tree.bind("<ButtonPress-1>", self._on_drag_start)
        self.tree.bind("<B1-Motion>", self._on_drag_motion)
        self.tree.bind("<ButtonRelease-1>", self._on_drag_release)
        y_scroll = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.tree.yview)
        y_scroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=y_scroll.set)

        right = ttk.LabelFrame(content, style="Panel.TLabelframe", padding=8)
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(0, weight=1)
        right.columnconfigure(0, weight=1)

        right_canvas = tk.Canvas(right, highlightthickness=0, bg="#f1f1f1")
        right_canvas.grid(row=0, column=0, sticky="nsew")
        right_scroll = ttk.Scrollbar(right, orient=tk.VERTICAL, command=right_canvas.yview)
        right_scroll.grid(row=0, column=1, sticky="ns")
        right_canvas.configure(yscrollcommand=right_scroll.set)

        right_content = ttk.Frame(right_canvas, padding=6)
        right_content.columnconfigure(0, weight=1)
        right_window = right_canvas.create_window((0, 0), window=right_content, anchor="nw")

        def _sync_right_panel(_event: tk.Event) -> None:
            right_canvas.configure(scrollregion=right_canvas.bbox("all"))
            right_canvas.itemconfigure(right_window, width=right_canvas.winfo_width())

        def _on_right_mousewheel(event: tk.Event) -> None:
            # Windows / macOS
            if hasattr(event, "delta") and event.delta:
                step = -1 if event.delta > 0 else 1
                right_canvas.yview_scroll(step, "units")
                return
            # Linux (Button-4 / Button-5)
            if getattr(event, "num", None) == 4:
                right_canvas.yview_scroll(-1, "units")
            elif getattr(event, "num", None) == 5:
                right_canvas.yview_scroll(1, "units")

        def _bind_right_wheel(_event: tk.Event) -> None:
            right_canvas.bind_all("<MouseWheel>", _on_right_mousewheel)
            right_canvas.bind_all("<Button-4>", _on_right_mousewheel)
            right_canvas.bind_all("<Button-5>", _on_right_mousewheel)

        def _unbind_right_wheel(_event: tk.Event) -> None:
            right_canvas.unbind_all("<MouseWheel>")
            right_canvas.unbind_all("<Button-4>")
            right_canvas.unbind_all("<Button-5>")

        right_content.bind("<Configure>", _sync_right_panel)
        right_canvas.bind("<Configure>", _sync_right_panel)
        right_canvas.bind("<Enter>", _bind_right_wheel)
        right_canvas.bind("<Leave>", _unbind_right_wheel)
        right_content.bind("<Enter>", _bind_right_wheel)
        right_content.bind("<Leave>", _unbind_right_wheel)

        ttk.Label(right_content, text="Управление курсами", style="RightTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(right_content, text="Выбрано:", style="PickedTitle.TLabel", padding=(8, 8)).grid(row=1, column=0, sticky="ew", pady=(16, 0))
        ttk.Label(right_content, textvariable=self.selected_info, style="PickedInfo.TLabel", padding=(8, 8), wraplength=340).grid(row=2, column=0, sticky="ew")
        self.add_btn = ttk.Button(right_content, text="➕ Добавить", style="Action.TButton", command=self.add_entity)
        self.add_btn.grid(row=3, column=0, sticky="ew", pady=(18, 10))
        self.edit_btn = ttk.Button(right_content, text="✎ Редактировать", style="Action.TButton", command=self.edit_entity)
        self.edit_btn.grid(row=4, column=0, sticky="ew", pady=10)
        self.del_btn = ttk.Button(right_content, text="✕ Удалить", style="Action.TButton", command=self.delete_entity)
        self.del_btn.grid(row=5, column=0, sticky="ew", pady=10)
        bottom = ttk.Frame(right_content)
        bottom.grid(row=6, column=0, sticky="ew", pady=(18, 0))
        bottom.columnconfigure(0, weight=1)
        ttk.Label(
            bottom,
            text="1. Выберите кафедру, чтобы добавить группу\n2. Выберите группу, чтобы добавить студента\n3. Выберите запись для редактирования или удаления",
            style="Hint.TLabel",
            padding=(10, 12),
            justify=tk.LEFT,
        ).grid(row=0, column=0, sticky="ew")

        ttk.Button(bottom, text="Журнал действий", command=self.open_logs).grid(row=1, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(bottom, text="Экспорт JSON", command=self.export_json).grid(row=2, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(bottom, text="Экспорт XML", command=self.export_xml).grid(row=3, column=0, sticky="ew", pady=(10, 0))
        self._update_buttons(None)

        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label="Добавить", command=self.add_entity)
        menu.add_command(label="Редактировать", command=self.edit_entity)
        menu.add_command(label="Удалить", command=self.delete_entity)
        self.context_menu = menu

    def log(self, action: str, entity_type: str, entity_id: int = 0, details: str = "") -> None:
        self.conn.execute(
            "INSERT INTO action_logs(user_login, action, entity_type, entity_id, details, created_at) VALUES(?, ?, ?, ?, ?, ?)",
            (
                self.user_login,
                action,
                entity_type,
                int(entity_id),
                details,
                datetime.now().isoformat(sep=" ", timespec="seconds"),
            ),
        )

    @staticmethod
    def _fio(last_name: str, first_name: str, middle_name: str | None) -> str:
        return f"{last_name} {first_name}{(' ' + middle_name) if middle_name else ''}"

    def _selected(self) -> tuple[str, int] | None:
        selected = self.tree.selection()
        if not selected:
            return None
        vals = self.tree.item(selected[0], "values")
        return (vals[0], int(vals[1])) if vals else None

    def _dummy_child(self, parent_iid: str) -> None:
        self.tree.insert(parent_iid, tk.END, text="", values=("__dummy__", 0))

    def _has_only_dummy(self, parent_iid: str) -> bool:
        children = self.tree.get_children(parent_iid)
        if len(children) != 1:
            return False
        vals = self.tree.item(children[0], "values")
        return bool(vals) and vals[0] == "__dummy__"

    def _clear_children(self, parent_iid: str) -> None:
        for child in self.tree.get_children(parent_iid):
            self.tree.delete(child)

    def refresh_roots(self) -> None:
        self.node_index.clear()
        for child in self.tree.get_children():
            self.tree.delete(child)
        deps = self.conn.execute(
            "SELECT d.id, d.name, d.code, COUNT(g.id) AS group_count "
            "FROM department d LEFT JOIN student_group g ON g.department_id = d.id "
            "GROUP BY d.id ORDER BY d.name"
        ).fetchall()
        for dep in deps:
            dep_iid = self.tree.insert("", tk.END, text=dep["name"], values=("department", dep["id"]))
            self.node_index[("department", dep["id"])] = dep_iid
            if dep["group_count"] and int(dep["group_count"]) > 0:
                self._dummy_child(dep_iid)

    def _load_groups(self, dep_id: int, dep_iid: str) -> None:
        self._clear_children(dep_iid)
        groups = self.conn.execute(
            "SELECT g.id, g.name, g.course, COUNT(s.id) AS student_count "
            "FROM student_group g LEFT JOIN student s ON s.student_group_id = g.id "
            "WHERE g.department_id = ? GROUP BY g.id ORDER BY g.name",
            (dep_id,),
        ).fetchall()
        for grp in groups:
            grp_iid = self.tree.insert(
                dep_iid,
                tk.END,
                text=f"{grp['name']}  |  курс: {grp['course']}",
                values=("student_group", grp["id"]),
            )
            self.node_index[("student_group", grp["id"])] = grp_iid
            if grp["student_count"] and int(grp["student_count"]) > 0:
                self._dummy_child(grp_iid)

    def _load_students(self, group_id: int, group_iid: str) -> None:
        self._clear_children(group_iid)
        students = self.conn.execute(
            "SELECT id, last_name, first_name, middle_name FROM student WHERE student_group_id = ? ORDER BY last_name, first_name",
            (group_id,),
        ).fetchall()
        for st in students:
            st_iid = self.tree.insert(
                group_iid,
                tk.END,
                text=self._fio(st["last_name"], st["first_name"], st["middle_name"]),
                values=("student", st["id"]),
            )
            self.node_index[("student", st["id"])] = st_iid

    def _on_open_node(self, _event: tk.Event) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        vals = self.tree.item(iid, "values")
        if not vals or not self._has_only_dummy(iid):
            return
        kind, entity_id = vals[0], int(vals[1])
        if kind == "department":
            self._load_groups(entity_id, iid)
        elif kind == "student_group":
            self._load_students(entity_id, iid)

    def _show_context_menu(self, event: tk.Event) -> None:
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
        selected = self._selected()
        if selected and selected[0] == "student":
            self.context_menu.entryconfigure("Добавить", state="disabled")
        else:
            self.context_menu.entryconfigure("Добавить", state="normal")
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def _on_drag_start(self, event: tk.Event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            self.drag_item_id = None
            return
        vals = self.tree.item(iid, "values")
        if vals and vals[0] == "student":
            self.drag_item_id = iid
        else:
            self.drag_item_id = None

    def _on_drag_motion(self, event: tk.Event) -> None:
        if not self.drag_item_id:
            return
        target_iid = self.tree.identify_row(event.y)
        if not target_iid:
            return
        vals = self.tree.item(target_iid, "values")
        if not vals:
            return
        # highlight only valid drop targets (groups)
        if vals[0] == "student_group":
            self.tree.selection_set(target_iid)
        elif vals[0] == "student":
            parent = self.tree.parent(target_iid)
            if parent and (self.tree.item(parent, "values") or [None])[0] == "student_group":
                self.tree.selection_set(parent)

    def _on_drag_release(self, event: tk.Event) -> None:
        if not self.drag_item_id:
            return
        source_iid = self.drag_item_id
        self.drag_item_id = None

        raw_target = self.tree.identify_row(event.y)
        if not raw_target or raw_target == source_iid:
            return
        src_vals = self.tree.item(source_iid, "values")
        if not src_vals:
            return
        if src_vals[0] != "student":
            return

        # Resolve drop target to a student_group node
        target_iid = raw_target
        tgt_vals = self.tree.item(target_iid, "values")
        if not tgt_vals:
            return
        if tgt_vals[0] == "__dummy__":
            target_iid = self.tree.parent(target_iid)
            tgt_vals = self.tree.item(target_iid, "values")
        elif tgt_vals[0] == "student":
            target_iid = self.tree.parent(target_iid)
            tgt_vals = self.tree.item(target_iid, "values")
        if not tgt_vals or tgt_vals[0] != "student_group":
            return

        student_id = int(src_vals[1])
        new_group_id = int(tgt_vals[1])
        row = self.conn.execute("SELECT student_group_id FROM student WHERE id = ?", (student_id,)).fetchone()
        if not row:
            return
        old_group_id = int(row[0]) if row[0] is not None else 0
        if old_group_id == new_group_id:
            return

        self.conn.execute("UPDATE student SET student_group_id = ? WHERE id = ?", (new_group_id, student_id))
        self.log("MOVE", "Student", student_id, f"Перенос из группы {old_group_id} в {new_group_id}")
        self.conn.commit()

        # If target has dummy, remove it and move student into target
        if self._has_only_dummy(target_iid):
            self._clear_children(target_iid)
        self.tree.move(source_iid, target_iid, tk.END)

        # Remove from old parent if needed
        # (nothing else needed; Treeview move already updated UI)


    def _on_select(self, _event: tk.Event) -> None:
        selected = self._selected()
        self._update_buttons(selected)
        if not selected:
            self.selected_info.set("Ничего не выбрано")
            return
        kind, entity_id = selected
        if kind == "department":
            row = self.conn.execute(
                "SELECT d.name, d.code, COUNT(g.id) FROM department d LEFT JOIN student_group g ON g.department_id = d.id WHERE d.id = ? GROUP BY d.id",
                (entity_id,),
            ).fetchone()
            self.selected_info.set(f"{row[0]}\nКод: {row[1]}\nГрупп: {row[2]}")
        elif kind == "student_group":
            row = self.conn.execute(
                "SELECT g.name, g.course, d.name, COUNT(s.id) FROM student_group g LEFT JOIN department d ON d.id = g.department_id LEFT JOIN student s ON s.student_group_id = g.id WHERE g.id = ? GROUP BY g.id",
                (entity_id,),
            ).fetchone()
            self.selected_info.set(f"{row[0]}\nКурс: {row[1]}\nКафедра: {row[2]}\nСтудентов: {row[3]}")
        else:
            row = self.conn.execute("SELECT last_name, first_name, middle_name, email, phone FROM student WHERE id = ?", (entity_id,)).fetchone()
            self.selected_info.set(f"{self._fio(row[0], row[1], row[2])}\nEmail: {row[3]}\nТелефон: {row[4] or 'нет'}")

    def _update_buttons(self, selected: tuple[str, int] | None) -> None:
        self.edit_btn.state(["disabled"])
        self.del_btn.state(["disabled"])
        self.add_btn.state(["!disabled"])
        if not selected:
            self.add_btn.configure(text="➕ Добавить кафедру")
            return
        self.edit_btn.state(["!disabled"])
        self.del_btn.state(["!disabled"])
        if selected[0] == "department":
            self.add_btn.configure(text="➕ Добавить группу")
        elif selected[0] == "student_group":
            self.add_btn.configure(text="➕ Добавить студента")
        else:
            self.add_btn.configure(text="➕ Добавление недоступно")
            self.add_btn.state(["disabled"])

    def add_entity(self) -> None:
        selected = self._selected()
        if not selected:
            dlg = EntityDialog(self, "Добавить кафедру", [("name", "Название"), ("code", "Код")])
            if dlg.result and dlg.result["name"] and dlg.result["code"]:
                cur = self.conn.execute("INSERT INTO department(name, code) VALUES(?, ?)", (dlg.result["name"], dlg.result["code"]))
                self.log("CREATE", "Department", cur.lastrowid, dlg.result["name"])
                self.conn.commit()
                dep_iid = self.tree.insert("", tk.END, text=dlg.result["name"], values=("department", cur.lastrowid))
                self.node_index[("department", cur.lastrowid)] = dep_iid
            return
        kind, entity_id = selected
        if kind == "department":
            dlg = EntityDialog(self, "Добавить группу", [("name", "Название группы"), ("course", "Курс (1-6)")])
            if not dlg.result:
                return
            try:
                course = int(dlg.result["course"])
            except ValueError:
                messagebox.showerror("Ошибка", "Курс должен быть числом.")
                return
            if dlg.result["name"] and 1 <= course <= 6:
                cur = self.conn.execute(
                    "INSERT INTO student_group(name, course, department_id) VALUES(?, ?, ?)",
                    (dlg.result["name"], course, entity_id),
                )
                self.log("CREATE", "StudentGroup", cur.lastrowid, f"{dlg.result['name']} (курс {course})")
                self.conn.commit()
                dep_iid = self.node_index.get(("department", entity_id))
                if dep_iid:
                    # If groups loaded, insert into tree; otherwise ensure plus sign
                    if self._has_only_dummy(dep_iid):
                        # keep dummy; actual load later
                        return
                    if len(self.tree.get_children(dep_iid)) == 0:
                        self._dummy_child(dep_iid)
                        return
                    grp_iid = self.tree.insert(
                        dep_iid,
                        tk.END,
                        text=f"{dlg.result['name']}  |  курс: {course}",
                        values=("student_group", cur.lastrowid),
                    )
                    self.node_index[("student_group", cur.lastrowid)] = grp_iid
            return
        if kind == "student_group":
            dlg = EntityDialog(self, "Добавить студента", [("last_name", "Фамилия"), ("first_name", "Имя"), ("middle_name", "Отчество"), ("email", "Email"), ("phone", "Телефон")])
            if dlg.result and dlg.result["last_name"] and dlg.result["first_name"] and dlg.result["email"]:
                cur = self.conn.execute(
                    "INSERT INTO student(last_name, first_name, middle_name, email, phone, student_group_id) VALUES(?, ?, ?, ?, ?, ?)",
                    (dlg.result["last_name"], dlg.result["first_name"], dlg.result["middle_name"] or None, dlg.result["email"], dlg.result["phone"] or None, entity_id),
                )
                self.log("CREATE", "Student", cur.lastrowid, f"{dlg.result['last_name']} {dlg.result['first_name']}")
                self.conn.commit()
                grp_iid = self.node_index.get(("student_group", entity_id))
                if grp_iid:
                    if self._has_only_dummy(grp_iid):
                        return
                    if len(self.tree.get_children(grp_iid)) == 0:
                        self._dummy_child(grp_iid)
                        return
                    st_text = self._fio(dlg.result["last_name"], dlg.result["first_name"], dlg.result["middle_name"] or None)
                    st_iid = self.tree.insert(grp_iid, tk.END, text=st_text, values=("student", cur.lastrowid))
                    self.node_index[("student", cur.lastrowid)] = st_iid

    def edit_entity(self) -> None:
        selected = self._selected()
        if not selected:
            return
        kind, entity_id = selected
        if kind == "department":
            row = self.conn.execute("SELECT name, code FROM department WHERE id = ?", (entity_id,)).fetchone()
            dlg = EntityDialog(self, "Редактировать кафедру", [("name", "Название"), ("code", "Код")], {"name": row[0], "code": row[1]})
            if dlg.result and dlg.result["name"] and dlg.result["code"]:
                self.conn.execute("UPDATE department SET name = ?, code = ? WHERE id = ?", (dlg.result["name"], dlg.result["code"], entity_id))
                self.log("UPDATE", "Department", entity_id, dlg.result["name"])
                self.conn.commit()
                iid = self.node_index.get(("department", entity_id))
                if iid:
                    self.tree.item(iid, text=dlg.result["name"])
        elif kind == "student_group":
            row = self.conn.execute("SELECT name, course FROM student_group WHERE id = ?", (entity_id,)).fetchone()
            dlg = EntityDialog(self, "Редактировать группу", [("name", "Название"), ("course", "Курс (1-6)")], {"name": row[0], "course": str(row[1])})
            if not dlg.result:
                return
            try:
                course = int(dlg.result["course"])
            except ValueError:
                messagebox.showerror("Ошибка", "Курс должен быть числом.")
                return
            if dlg.result["name"] and 1 <= course <= 6:
                self.conn.execute("UPDATE student_group SET name = ?, course = ? WHERE id = ?", (dlg.result["name"], course, entity_id))
                self.log("UPDATE", "StudentGroup", entity_id, f"{dlg.result['name']} (курс {course})")
                self.conn.commit()
                iid = self.node_index.get(("student_group", entity_id))
                if iid:
                    self.tree.item(iid, text=f"{dlg.result['name']}  |  курс: {course}")
        else:
            row = self.conn.execute("SELECT last_name, first_name, middle_name, email, phone FROM student WHERE id = ?", (entity_id,)).fetchone()
            dlg = EntityDialog(
                self,
                "Редактировать студента",
                [("last_name", "Фамилия"), ("first_name", "Имя"), ("middle_name", "Отчество"), ("email", "Email"), ("phone", "Телефон")],
                {"last_name": row[0], "first_name": row[1], "middle_name": row[2] or "", "email": row[3], "phone": row[4] or ""},
            )
            if dlg.result and dlg.result["last_name"] and dlg.result["first_name"] and dlg.result["email"]:
                self.conn.execute(
                    "UPDATE student SET last_name = ?, first_name = ?, middle_name = ?, email = ?, phone = ? WHERE id = ?",
                    (dlg.result["last_name"], dlg.result["first_name"], dlg.result["middle_name"] or None, dlg.result["email"], dlg.result["phone"] or None, entity_id),
                )
                self.log("UPDATE", "Student", entity_id, f"{dlg.result['last_name']} {dlg.result['first_name']}")
                self.conn.commit()
                iid = self.node_index.get(("student", entity_id))
                if iid:
                    self.tree.item(iid, text=self._fio(dlg.result["last_name"], dlg.result["first_name"], dlg.result["middle_name"] or None))

    def delete_entity(self) -> None:
        selected = self._selected()
        if not selected or not messagebox.askyesno("Подтверждение", "Удалить выбранную запись?"):
            return
        kind, entity_id = selected
        if kind == "department":
            name_row = self.conn.execute("SELECT name FROM department WHERE id = ?", (entity_id,)).fetchone()
            self.conn.execute("DELETE FROM department WHERE id = ?", (entity_id,))
            self.log("DELETE", "Department", entity_id, name_row[0] if name_row else "")
        elif kind == "student_group":
            name_row = self.conn.execute("SELECT name FROM student_group WHERE id = ?", (entity_id,)).fetchone()
            self.conn.execute("DELETE FROM student_group WHERE id = ?", (entity_id,))
            self.log("DELETE", "StudentGroup", entity_id, name_row[0] if name_row else "")
        else:
            name_row = self.conn.execute("SELECT last_name, first_name FROM student WHERE id = ?", (entity_id,)).fetchone()
            self.conn.execute("DELETE FROM student WHERE id = ?", (entity_id,))
            if name_row:
                self.log("DELETE", "Student", entity_id, f"{name_row[0]} {name_row[1]}")
            else:
                self.log("DELETE", "Student", entity_id, "")
        self.conn.commit()
        self.selected_info.set("Ничего не выбрано")
        iid = self.node_index.pop((kind, entity_id), None)
        if iid:
            self.tree.delete(iid)
        self._update_buttons(None)

    def open_logs(self) -> None:
        LogWindow(self, self.conn)

    def export_json(self) -> None:
        data = []
        deps = self.conn.execute("SELECT id, name, code FROM department ORDER BY name").fetchall()
        for d in deps:
            groups = self.conn.execute(
                "SELECT id, name, course FROM student_group WHERE department_id = ? ORDER BY name",
                (d["id"],),
            ).fetchall()
            groups_data = []
            for g in groups:
                students = self.conn.execute(
                    "SELECT id, last_name, first_name, middle_name, email, phone FROM student WHERE student_group_id = ? ORDER BY last_name, first_name",
                    (g["id"],),
                ).fetchall()
                groups_data.append(
                    {
                        "id": g["id"],
                        "name": g["name"],
                        "course": g["course"],
                        "students": [
                            {
                                "id": s["id"],
                                "last_name": s["last_name"],
                                "first_name": s["first_name"],
                                "middle_name": s["middle_name"],
                                "email": s["email"],
                                "phone": s["phone"],
                            }
                            for s in students
                        ],
                    }
                )
            data.append({"id": d["id"], "name": d["name"], "code": d["code"], "groups": groups_data})

        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        self.log("EXPORT", "Tree", 0, f"JSON: {path}")
        self.conn.commit()
        messagebox.showinfo("Успех", "Экспорт JSON выполнен.")

    def export_xml(self) -> None:
        root = ET.Element("departments")
        deps = self.conn.execute("SELECT id, name, code FROM department ORDER BY name").fetchall()
        for d in deps:
            d_node = ET.SubElement(root, "department", id=str(d["id"]), name=d["name"], code=d["code"])
            groups = self.conn.execute(
                "SELECT id, name, course FROM student_group WHERE department_id = ? ORDER BY name",
                (d["id"],),
            ).fetchall()
            for g in groups:
                g_node = ET.SubElement(d_node, "group", id=str(g["id"]), name=g["name"], course=str(g["course"]))
                students = self.conn.execute(
                    "SELECT id, last_name, first_name, middle_name, email, phone FROM student WHERE student_group_id = ? ORDER BY last_name, first_name",
                    (g["id"],),
                ).fetchall()
                for s in students:
                    ET.SubElement(
                        g_node,
                        "student",
                        id=str(s["id"]),
                        last_name=s["last_name"],
                        first_name=s["first_name"],
                        middle_name=s["middle_name"] or "",
                        email=s["email"],
                        phone=s["phone"] or "",
                    )

        path = filedialog.asksaveasfilename(defaultextension=".xml", filetypes=[("XML", "*.xml")])
        if not path:
            return
        ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
        self.log("EXPORT", "Tree", 0, f"XML: {path}")
        self.conn.commit()
        messagebox.showinfo("Успех", "Экспорт XML выполнен.")

    def _on_close(self) -> None:
        self.conn.close()
        self.destroy()


class LogWindow(tk.Toplevel):
    def __init__(self, parent: tk.Tk, conn: sqlite3.Connection) -> None:
        super().__init__(parent)
        self.title("Журнал действий")
        self.geometry("980x520")
        self.minsize(820, 420)
        self.conn = conn

        cols = ("id", "user", "action", "entity", "entity_id", "details", "created")
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(frame, columns=cols, show="headings")
        self.tree.grid(row=1, column=0, sticky="nsew")
        y_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        y_scroll.grid(row=1, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=y_scroll.set)

        headings = [
            ("id", "ID", 70),
            ("user", "Пользователь", 120),
            ("action", "Операция", 90),
            ("entity", "Сущность", 130),
            ("entity_id", "ID сущности", 90),
            ("details", "Описание", 320),
            ("created", "Дата/время", 160),
        ]
        for col, title, width in headings:
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor=tk.W if col in ("details", "entity") else tk.CENTER)

        ttk.Button(frame, text="Обновить", command=self.refresh).grid(row=0, column=0, sticky="w", pady=(0, 10))
        self.refresh()

    def refresh(self) -> None:
        for child in self.tree.get_children():
            self.tree.delete(child)
        rows = self.conn.execute(
            "SELECT id, user_login, action, entity_type, entity_id, details, created_at "
            "FROM action_logs ORDER BY id DESC LIMIT 2000"
        ).fetchall()
        for r in rows:
            self.tree.insert(
                "",
                tk.END,
                values=(r[0], r[1], r[2], r[3], r[4], r[5], r[6]),
            )


def run() -> None:
    login_window = LoginWindow()
    login_window.mainloop()
    if not login_window.auth_user:
        return
    app = App(login_window.auth_user)
    app.mainloop()


if __name__ == "__main__":
    run()
