import os
import re
import csv
import click
import string
import secrets
import sqlite3
from io import StringIO
from datetime import datetime

import pydicom
from pydicom.errors import InvalidDicomError
from dotenv import load_dotenv

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
)
from flask import send_from_directory, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

from database_init import inicializuj_databazi
from dicom_logic import get_drl_metadata, generate_thumb

# Načtení proměnných prostředí z .env
load_dotenv()

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif"}

# Inicializace Flask aplikace
app = Flask(__name__, instance_relative_config=True)

# 1. Správné předávání IP adres uživatelů za Nginx / Docker proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# 2. Tajný klíč a velikostní limity
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY není nastavena v prostředí.")

app.config["MAX_CONTENT_LENGTH"] = (
    512 * 1024 * 1024
)  # Ochrana disku/RAM (max 512 MB per request)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
)
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 8  # 8 hodin

# CSRF Ochrana
csrf = CSRFProtect(app)

# 3. Cesty navázané výhradně na app.instance_path (nezávislé na pracovním adresáři)
db_path = os.path.join(app.instance_path, os.getenv("DATABASE_NAME", "moje_data.db"))

UPLOAD_ROOT = os.path.join(app.instance_path, "uploads")
FOTKY_FOLDER = os.path.join(UPLOAD_ROOT, "fotky")
DICOM_RAW_FOLDER = os.path.join(UPLOAD_ROOT, "dicom_originaly")
DICOM_THUMB_FOLDER = os.path.join(UPLOAD_ROOT, "dicom_nahledy")

# Automatické vytvoření složek v instance/
for slozka in [app.instance_path, FOTKY_FOLDER, DICOM_RAW_FOLDER, DICOM_THUMB_FOLDER]:
    os.makedirs(slozka, exist_ok=True)


def get_db_connection():
    """Vrátí připojení k databázi se standardním row_factory pro čtení podle názvů sloupců."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


# 4. Limiter s konfigurací z .env (memory pro vývoj, Redis pro více workerů v produkci)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
)


# 5. CLI příkaz pro inicializaci databáze namísto volání při importu
@app.cli.command("init-db")
def init_db_command():
    """Vytvoří nebo aktualizuje databázové schématu."""
    print(f"Kontroluji (aktualizuji) strukturu databáze: {db_path}")
    inicializuj_databazi(db_path)
    print("Inicializace databáze dokončena.")


@app.cli.command("make-admin")
@click.argument("identifier")
def make_admin_command(identifier):
    """Povýší zadaného uživatele (podle jména nebo e-mailu) na roli admin."""
    if not os.path.exists(db_path):
        print(
            f"❌ Chyba: Databáze nebyla nalezena v: {db_path}\nSpusťte nejdříve 'flask init-db'."
        )
        return

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        # Hledá podle jména NEBO e-mailu
        cursor.execute(
            "UPDATE uzivatele SET role = 'admin' WHERE jmeno = ? OR email = ?",
            (identifier, identifier),
        )

        if cursor.rowcount > 0:
            print(f"✅ Uživatel '{identifier}' byl úspěšně povýšen na admina.")
        else:
            print(
                f"❌ Chyba: Uživatel s jménem nebo e-mailem '{identifier}' nebyl nalezen."
            )


# --- POMOCNÁ FUNKCE PRO KONTROLU HESLA ---
def je_heslo_bezpecne(heslo):
    """
    Zkontroluje, zda má heslo alespoň 8 znaků, obsahuje velké písmeno,
    malé písmeno a číslici.
    """
    if len(heslo) < 8:
        return False
    if not re.search(r"[a-z]", heslo):
        return False
    if not re.search(r"[A-Z]", heslo):
        return False
    if not re.search(r"[0-9]", heslo):
        return False
    return True


# --- CONTEXT PROCESSOR PRO TYPICKÉ HODNOTY V NAVBARU ---
@app.context_processor
def inject_typicke_hodnoty():
    typicke_hodnoty = {}
    if "user_id" in session:
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()

                cursor.execute(
                    "SELECT kategorie, prumerny_kap, datum_aktualizace FROM typicke_hodnoty WHERE uzivatel_id = ?",
                    (session["user_id"],),
                )
                for radek in cursor.fetchall():
                    # Převedeme formát z databáze na hezčí datum
                    try:
                        datum_obj = datetime.strptime(
                            radek["datum_aktualizace"], "%Y-%m-%d %H:%M:%S"
                        )
                        formatovane_datum = datum_obj.strftime("%d.%m.%Y")
                    except (ValueError, TypeError):
                        formatovane_datum = ""

                    # Uložíme si nyní obě hodnoty (KAP i datum) do slovníku pod danou kategorii
                    typicke_hodnoty[radek["kategorie"]] = {
                        "kap": radek["prumerny_kap"],
                        "datum": formatovane_datum,
                    }
        except sqlite3.OperationalError:
            pass
    return dict(typicke_hodnoty=typicke_hodnoty)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            flash("Sem mají přístup pouze vyvolení! 🛑", "danger")
            return redirect(url_for("index"))

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT role FROM uzivatele WHERE id = ?", (user_id,))
                user = cursor.fetchone()
        except sqlite3.Error:
            flash("Došlo k chybě při ověřování přístupu. 🛑", "danger")
            return redirect(url_for("index"))

        if not user or user["role"] != "admin":
            session.clear()
            flash("Sem mají přístup pouze vyvolení! 🛑", "danger")
            return redirect(url_for("index"))

        return f(*args, **kwargs)

    return decorated_function


@app.route("/")
def index():
    # Flask automaticky hledá ve složce 'templates'
    return render_template("index.html")


# --- ROUTA PRO ZOBRAZENÍ STRÁNKY REGISTRACE ---
@app.route("/registrace", methods=["GET"])
def registrace():
    # Jen vykreslí HTML šablonu, nic víc
    return render_template("registrace.html")


# --- API ROUTA PRO VYGENEROVÁNÍ HESLA ---
@app.route("/api/generovat-heslo", methods=["GET"])
def api_generovat_heslo():
    # U vygenerovaných hesel, která si uživatel nemusí pamatovat,
    # je dobrým zvykem dát rovnou větší délku (např. 12 nebo 16).
    # Můžeš ale klidně nechat 8.
    length = 12

    # 1. Garantujeme alespoň jeden znak z každé povinné skupiny
    password_chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]

    # 2. Zbytek doplníme náhodně z celé abecedy (včetně interpunkce)
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password_chars += [secrets.choice(alphabet) for _ in range(length - 3)]

    # 3. Seznam promícháme, aby první 3 znaky nebyly vždy (malé, velké, číslo).
    # Použijeme SystemRandom(), což je kryptograficky bezpečný generátor
    # (standardní random.shuffle z modulu random by nebyl pro hesla vhodný).
    secure_random = secrets.SystemRandom()
    secure_random.shuffle(password_chars)

    password = "".join(password_chars)

    return jsonify({"status": "success", "heslo": password}), 200


# --- 2. API ROUTA PRO ZPRACOVÁNÍ DAT (AJAX) ---
@app.route("/api/registrace", methods=["POST"])
@limiter.limit(
    "5 per hour"
)  # Ochrana: Z jedné IP adresy lze zkusit registraci jen 5x za hodinu!
def api_registrace():
    data = request.get_json()

    if not data:
        return jsonify({"status": "error", "zprava": "Chybí data požadavku"}), 400

    jmeno = data.get("jmeno")
    email = data.get("email")
    heslo_raw = data.get("heslo")

    # 1. Kontrola, zda jsou vyplněna všechna pole
    if not all([jmeno, email, heslo_raw]):
        return (
            jsonify({"status": "error", "zprava": "Všechna pole jsou povinná! ✍️"}),
            400,
        )

    # 2. Bezpečnostní kontrola síly hesla
    if not je_heslo_bezpecne(heslo_raw):
        return (
            jsonify(
                {
                    "status": "error",
                    "zprava": "Heslo musí mít alespoň 8 znaků, obsahovat malá i velká písmena a číslici. 🔒",
                }
            ),
            400,
        )

    ted = datetime.now()
    datum_reg = ted.strftime("%Y-%m-%d %H:%M:%S")
    heslo_hash = generate_password_hash(heslo_raw)

    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO uzivatele (jmeno, email, heslo_hash, datum_registrace) VALUES (?, ?, ?, ?)",
                (jmeno, email, heslo_hash, datum_reg),
            )
            conn.commit()

        return (
            jsonify(
                {
                    "status": "success",
                    "zprava": "Registrace proběhla úspěšně! ✅ Přesměrovávám...",
                    "redirect": url_for("prihlaseni"),
                }
            ),
            200,
        )

    except sqlite3.IntegrityError:
        return (
            jsonify(
                {"status": "error", "zprava": "Tento e-mail už je zaregistrován. ❌"}
            ),
            409,
        )
    except sqlite3.Error as e:
        return jsonify({"status": "error", "zprava": f"Chyba databáze: {e}"}), 500


# --- ROUTA PRO ZOBRAZENÍ STRÁNKY PŘIHLÁŠENÍ ---
@app.route("/prihlaseni", methods=["GET"])
def prihlaseni():
    # Jen vykreslí HTML šablonu
    return render_template("prihlaseni.html")


# --- 2. API ROUTA PRO ZPRACOVÁNÍ PŘIHLÁŠENÍ (AJAX) ---
@app.route("/api/prihlaseni", methods=["POST"])
@limiter.limit("10 per minute")
def api_prihlaseni():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"status": "error", "zprava": "Chybí data požadavku"}), 400

    email = data.get("email")
    heslo_zadane = data.get("heslo")

    if (
        not isinstance(email, str)
        or not isinstance(heslo_zadane, str)
        or not email
        or not heslo_zadane
    ):
        return jsonify({"status": "error", "zprava": "Zadejte e-mail i heslo."}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, heslo_hash, jmeno, role, je_blokovan "
            "FROM uzivatele WHERE email = ?",
            (email,),
        )
        radek = cursor.fetchone()

    # Stejná odpověď pro neexistující účet, špatné heslo i blokovaný účet.
    if not radek or not check_password_hash(radek["heslo_hash"], heslo_zadane):
        return (
            jsonify({"status": "error", "zprava": "Nesprávný e-mail nebo heslo."}),
            401,
        )

    if radek["je_blokovan"] == 1:
        return (
            jsonify({"status": "error", "zprava": "Nesprávný e-mail nebo heslo."}),
            401,
        )

    for key in ("user_id", "user_jmeno", "role"):
        session.pop(key, None)

    session["user_id"] = radek["id"]
    session["user_jmeno"] = radek["jmeno"]
    session["role"] = radek["role"]

    return (
        jsonify(
            {
                "status": "success",
                "zprava": "Vítejte zpět! 🎉 Přesměrovávám...",
                "redirect": url_for("index"),
            }
        ),
        200,
    )


# --- ROUTA PRO ADMIN ROZHRANÍ (admin.html) ---
@app.route("/admin")
@admin_required
def admin_panel():
    # Context manager 'with' automaticky spravuje transakce a zaručí uzavření spojení
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Načteme ostatní uživatele (mimo aktuálně přihlášeného admina)
        cursor.execute(
            "SELECT id, jmeno, email, role, je_blokovan FROM uzivatele WHERE id != ?",
            (session.get("user_id"),),
        )
        vsichni_uzivatele = cursor.fetchall()

    return render_template("admin.html", uzivatele=vsichni_uzivatele)


# API pro přepnutí blokace (AJAX)
@app.route("/api/admin/prepni-blokaci/<int:target_user_id>", methods=["POST"])
def api_prepni_blokaci(target_user_id):
    if session.get("role") != "admin":
        return jsonify({"status": "error", "zprava": "Neautorizovaný přístup"}), 403

    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            # Zjistíme aktuální stav a otočíme ho (0->1, 1->0)
            cursor.execute(
                "UPDATE uzivatele SET je_blokovan = 1 - je_blokovan WHERE id = ?",
                (target_user_id,),
            )
            conn.commit()
    except sqlite3.Error as e:
        return jsonify({"status": "error", "zprava": f"Chyba databáze: {e}"}), 500

    return jsonify({"status": "success", "zprava": "Stav uživatele byl změněn. ✅"})


# --- ROUTA PRO ZOBRAZENÍ GALERIE (moje_fotky.html) ---
@app.route("/moje-fotky")
def moje_fotky():
    uzivatel_id = session.get("user_id")
    if not uzivatel_id:
        flash("Pro zobrazení galerie se musíte přihlásit. 🔒")
        return redirect(url_for("prihlaseni"))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Vybereme fotky konkrétního uživatele, seřazené od nejnovějších
        cursor.execute(
            "SELECT id, nazev_souboru, cesta_k_souboru, datum_nahrani FROM fotky WHERE uzivatel_id = ? ORDER BY datum_nahrani DESC",
            (uzivatel_id,),
        )
        nahrane_fotky = cursor.fetchall()

    # Pošleme seznam fotek do šablony pod jménem 'fotky'
    return render_template("moje_fotky.html", fotky=nahrane_fotky)


# --- ROUTA PRO POSKYTNUTÍ OBRÁZKU PROHLÍŽEČI ---


# --- ROUTA PRO FOTKY Z GALERIE ---
@app.route("/uploads/fotky/<filename>")
def nahrana_fotka(filename):
    uzivatel_id = session.get("user_id")
    if not uzivatel_id:
        return jsonify({"status": "error", "zprava": "Neautorizováno."}), 401

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM fotky WHERE cesta_k_souboru = ? AND uzivatel_id = ?",
            (filename, uzivatel_id),
        )
        if cursor.fetchone() is None:
            return jsonify({"status": "error", "zprava": "Soubor nenalezen."}), 404

    return send_from_directory(FOTKY_FOLDER, filename)


# --- ROUTA PRO DICOM NÁHLEDY (PNG) ---
@app.route("/uploads/dicom-nahled/<filename>")
@limiter.exempt  # Prohlížeč může načítat mnoho náhledů najednou.
def dicom_nahled(filename):
    uzivatel_id = session.get("user_id")
    if not uzivatel_id:
        return jsonify({"status": "error", "zprava": "Neautorizováno."}), 401

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM dicom_snimky WHERE thumb_cesta = ? AND uzivatel_id = ?",
            (filename, uzivatel_id),
        )
        if cursor.fetchone() is None:
            return jsonify({"status": "error", "zprava": "Soubor nenalezen."}), 404

    return send_from_directory(DICOM_THUMB_FOLDER, filename)


# --- ROUTA PRO UPLOAD ---
@app.route("/api/nahrat-foto", methods=["POST"])
def api_nahrat_foto():
    # 1. Kontrola přihlášení
    uzivatel_id = session.get("user_id")
    if not uzivatel_id:
        return (
            jsonify(
                {"status": "error", "zprava": "Pro nahrávání se musíte přihlásit! 🔒"}
            ),
            401,
        )

    # 2. Získáme SEZNAM všech souborů pod klíčem 'fotky' (změněno z 'foto')
    soubory = request.files.getlist("fotky")

    # Kontrola, zda uživatel vůbec něco vybral
    if not soubory or soubory[0].filename == "":
        return (
            jsonify({"status": "error", "zprava": "Nevybral jsi žádný soubor! 📁"}),
            400,
        )

    uspesne_fotky = []  # Sem si uložíme data pro odeslání zpět do JS

    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            ted_datum_cas = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            for soubor in soubory:
                if soubor and soubor.filename != "":
                    bezpecny_nazev = secure_filename(soubor.filename)
                    jmeno, pripona = os.path.splitext(bezpecny_nazev)

                    if pripona.lower() not in ALLOWED_EXTENSIONS:
                        continue  # Nepovolený soubor přeskočíme a jdeme na další

                    # Přidali jsme %f (mikrosekundy), aby se fotky nahrané naráz nepřepsaly
                    cas_string = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                    novy_nazev = f"{jmeno}_{uzivatel_id}_{cas_string}{pripona}"

                    cesta_na_disk = os.path.join(FOTKY_FOLDER, novy_nazev)
                    soubor.save(cesta_na_disk)

                    cursor.execute(
                        "INSERT INTO fotky (nazev_souboru, cesta_k_souboru, uzivatel_id, datum_nahrani) VALUES (?, ?, ?, ?)",
                        (soubor.filename, novy_nazev, uzivatel_id, ted_datum_cas),
                    )
                    nove_id = cursor.lastrowid

                    uspesne_fotky.append(
                        {
                            "id": nove_id,
                            "nazev_souboru": soubor.filename,
                            "cesta_k_souboru": novy_nazev,
                            "datum_nahrani": ted_datum_cas,
                        }
                    )

            conn.commit()

        # Pokud se nahrála alespoň jedna fotka, vracíme úspěch
        if uspesne_fotky:
            return jsonify(
                {
                    "status": "success",
                    "zprava": f"Úspěšně nahráno {len(uspesne_fotky)} fotek! 🚀",
                    "fotky": uspesne_fotky,  # Posíláme POLE fotek, ne jen jednu
                }
            )
        return (
            jsonify(
                {
                    "status": "error",
                    "zprava": "Nepodařilo se nahrát žádný povolený soubor. 🚫",
                }
            ),
            400,
        )

    except Exception as e:
        return jsonify({"status": "error", "zprava": f"Chyba při ukládání: {e}"}), 500


# --- API ROUTA PRO SMAZÁNÍ FOTKY (AJAX) ---
@app.route("/api/smazat-foto/<int:foto_id>", methods=["DELETE"])
def api_smazat_foto(foto_id):
    # 1. Kontrola přihlášení
    uzivatel_id = session.get("user_id")
    if not uzivatel_id:
        return (
            jsonify(
                {"status": "error", "zprava": "Pro tuto akci se musíte přihlásit! 🔒"}
            ),
            401,
        )

    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            # 2. Zjistíme cestu k souboru a ověříme vlastníka
            cursor.execute(
                "SELECT cesta_k_souboru FROM fotky WHERE id = ? AND uzivatel_id = ?",
                (foto_id, uzivatel_id),
            )
            vysledek = cursor.fetchone()

            if vysledek:
                nazev_souboru_na_disku = vysledek[0]
                absolutni_cesta = os.path.join(FOTKY_FOLDER, nazev_souboru_na_disku)

                # 3. Smazání souboru z disku (pokud existuje)
                if os.path.exists(absolutni_cesta):
                    os.remove(absolutni_cesta)

                # 4. Smazání záznamu z databáze
                cursor.execute(
                    "DELETE FROM fotky WHERE id = ? AND uzivatel_id = ?",
                    (foto_id, uzivatel_id),
                )
                conn.commit()
                return (
                    jsonify(
                        {
                            "status": "success",
                            "zprava": "Fotka byla úspěšně smazána. 🗑️",
                        }
                    ),
                    200,
                )

            return (
                jsonify(
                    {
                        "status": "error",
                        "zprava": "Fotka nebyla nalezena nebo k ní nemáte přístup. 🚫",
                    }
                ),
                404,
            )

    except Exception as e:
        return jsonify({"status": "error", "zprava": f"Chyba při mazání: {e}"}), 500


# --- ROUTA PRO STAŽENÍ FOTKY ---
@app.route("/stahnout-foto/<int:foto_id>")
def stahnout_foto(foto_id):
    # 1. Kontrola, zda je uživatel přihlášen
    uzivatel_id = session.get("user_id")
    if not uzivatel_id:
        flash("Pro stahování souborů se musíte přihlásit. 🔒")
        return redirect(url_for("prihlaseni"))

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Přidali jsme do výběru i 'nazev_souboru', což je ten původní hezký název
        cursor.execute(
            "SELECT cesta_k_souboru, nazev_souboru FROM fotky WHERE id = ? AND uzivatel_id = ?",
            (foto_id, uzivatel_id),
        )
        vysledek = cursor.fetchone()

    # 3. Pokud záznam existuje, pošleme fotku ke stažení
    if vysledek:
        nazev_souboru_na_disku = vysledek[0]
        puvodni_nazev = vysledek[1]  # Vytáhneme původní název z databáze

        # Přidán parametr download_name, aby se fotka stáhla pod původním jménem!
        return send_from_directory(
            FOTKY_FOLDER,
            nazev_souboru_na_disku,
            as_attachment=True,
            download_name=puvodni_nazev,
        )

    # Pokud soubor neexistuje nebo patří někomu jinému
    flash("Fotka nebyla nalezena nebo k ní nemáte přístup. 🚫")
    return redirect(url_for("moje_fotky"))


# --- ROUTA PRO ZOBRAZENÍ DICOM ARCHIVU (muj_dicom.html) ---
# Routa přijme volitelný parametr 'kategorie', výchozí je 'vse'
@app.route("/muj-dicom", defaults={"kategorie": "vse"})
@app.route("/muj-dicom/<kategorie>")
def muj_dicom(kategorie):
    uzivatel_id = session.get("user_id")
    if not uzivatel_id:
        flash("Pro přístup k DICOM archivu se musíte přihlásit. 🔒")
        return redirect(url_for("prihlaseni"))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Rozhodnutí podle vybrané kategorie
        if kategorie == "vse":
            cursor.execute(
                "SELECT * FROM dicom_snimky WHERE uzivatel_id = ? ORDER BY datum_nahrani DESC",
                (uzivatel_id,),
            )
        else:
            cursor.execute(
                "SELECT * FROM dicom_snimky WHERE uzivatel_id = ? AND kategorie = ? ORDER BY datum_nahrani DESC",
                (uzivatel_id, kategorie),
            )

        snimky = cursor.fetchall()

    # Do šablony pošleme i aktuální kategorii, abychom podle ní mohli upravit např. nadpis stránky
    return render_template(
        "muj_dicom.html", dicom_snimky=snimky, aktivni_kategorie=kategorie
    )


# --- API PRO NAHRÁNÍ A EXTRAKCI METADAT ---
@app.route("/api/nahrat-dicom", methods=["POST"])
def api_nahrat_dicom():
    uzivatel_id = session.get("user_id")
    if not uzivatel_id:
        return jsonify({"status": "error", "zprava": "Nepřihlášený uživatel."}), 401

    soubory = request.files.getlist("dicom_files")
    # ZÍSKÁNÍ KATEGORIE Z FORM DATA (pokud není zadána, uloží se jako 'vse')
    kategorie = request.form.get("kategorie", "vse")

    if not soubory or soubory[0].filename == "":
        return jsonify({"status": "error", "zprava": "Žádné soubory k nahrání."}), 400

    uspesne = 0
    preskocene = 0  # NOVÉ: Počítadlo chybných/neplatných souborů
    vytvorene_soubory = []
    vytvorene_nahledy = []

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        for soubor in soubory:
            bezpecny_nazev = secure_filename(soubor.filename)
            cas_prefix = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            unikatni_nazev = f"{cas_prefix}_{uzivatel_id}_{bezpecny_nazev}"
            cesta_dcm = os.path.join(DICOM_RAW_FOLDER, unikatni_nazev)

            soubor.save(cesta_dcm)
            vytvorene_soubory.append(cesta_dcm)

            # --- NOVÉ ZABEZPEČENÍ: Kontrola platnosti DICOMu ihned po uložení ---
            try:
                # stop_before_pixels=True zaručí, že je kontrola bleskurychlá
                pydicom.dcmread(cesta_dcm, stop_before_pixels=True)
            except InvalidDicomError:
                # Soubor není DICOM (např. přejmenovaný .jpg, prázdný soubor, atd.)
                os.remove(cesta_dcm)  # Odstraníme "odpad" z disku
                preskocene += 1
                continue  # Přeskočí zbytek kódu pro tento soubor a jde na další
            except Exception:
                # Jiná chyba při čtení (např. silně poškozený soubor)
                os.remove(cesta_dcm)
                preskocene += 1
                continue
            # ---------------------------------------------------------------------

            # Pokud kontrola prošla, pokračujeme tvým původním kódem
            meta = get_drl_metadata(cesta_dcm)
            if "error" in meta:
                os.remove(cesta_dcm)
                preskocene += 1
                continue

            thumb_nazev = f"thumb_{unikatni_nazev}.png"
            vytvorena_cesta_nahledu = generate_thumb(
                cesta_dcm, DICOM_THUMB_FOLDER, thumb_nazev
            )
            if vytvorena_cesta_nahledu is None:
                os.remove(cesta_dcm)
                preskocene += 1
                continue

            vytvorene_nahledy.append(
                os.path.join(DICOM_THUMB_FOLDER, vytvorena_cesta_nahledu)
            )

            cursor.execute(
                """
                INSERT INTO dicom_snimky (
                    nazev_souboru, cesta_k_souboru, thumb_cesta, uzivatel_id, datum_nahrani, kategorie,
                    patient_id, study_date, weight, kap, description, sex,
                    manufacturer, model_name, institution_name, department_name, station_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    soubor.filename,
                    unikatni_nazev,
                    thumb_nazev,
                    uzivatel_id,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    kategorie,
                    meta.get("PatientID"),
                    meta.get("StudyDate"),
                    meta.get("Weight"),
                    meta.get("KAP"),
                    meta.get("StudyDescription"),
                    meta.get("PatientSex"),
                    meta.get("Manufacturer"),
                    meta.get("ManufacturerModelName"),
                    meta.get("InstitutionName"),
                    meta.get("InstitutionalDepartmentName"),
                    meta.get("StationName"),
                ),
            )
            uspesne += 1

        conn.commit()

        # Dynamická odpověď podle toho, zda se nějaké soubory přeskočily
        if preskocene > 0:
            zprava_vysledku = f"Nahráno {uspesne} souborů. ({preskocene} souborů vyřazeno - neplatný formát DICOM)."
        else:
            zprava_vysledku = f"Nahráno a analyzováno {uspesne} souborů."

        return jsonify({"status": "success", "zprava": zprava_vysledku})

    except Exception as e:
        # Tento globální blok teď zachytí už jen fatální chyby (např. výpadek databáze)
        for cesta in vytvorene_soubory + vytvorene_nahledy:
            if os.path.exists(cesta):
                os.remove(cesta)
        conn.rollback()
        return (
            jsonify(
                {"status": "error", "zprava": f"Chyba databáze nebo serveru: {str(e)}"}
            ),
            500,
        )
    finally:
        conn.close()


# --- API PRO VÝPOČET STATISTIK Z VYBRANÝCH SOUBORŮ ---
@app.route("/api/analyzovat-vyber", methods=["POST"])
def api_analyzovat_vyber():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "error", "zprava": "Neplatná data požadavku."}), 400

    ids = data.get("ids", [])

    if not ids:
        return (
            jsonify({"status": "error", "zprava": "Nebyly vybrány žádné snímky."}),
            400,
        )

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # ZMĚNA: Přidáno načtení sloupce 'study_date'
            dotaz = f"SELECT kap, weight, sex, study_date FROM dicom_snimky WHERE id IN ({','.join(['?']*len(ids))}) AND uzivatel_id = ?"
            cursor.execute(dotaz, ids + [session.get("user_id")])
            vysledky = cursor.fetchall()
    except sqlite3.Error as e:
        return jsonify({"status": "error", "zprava": f"Chyba databáze: {e}"}), 500

    if not vysledky:
        return jsonify({"status": "error", "zprava": "Data nenalezena."}), 404

    hodnoty_kap = []
    hodnoty_hmotnost = []

    # Počítadla pro pohlaví
    pocet_muzu = 0
    pocet_zen = 0

    # NOVÉ: Seznam pro zpracování dat
    data_vysetreni = []

    for r in vysledky:
        kap_val = r["kap"]
        if kap_val and kap_val != "N/A":
            try:
                hodnoty_kap.append(float(kap_val))
            except ValueError:
                pass

        weight_val = r["weight"]
        if weight_val and weight_val != "N/A":
            try:
                hodnoty_hmotnost.append(float(weight_val))
            except ValueError:
                pass

        # Zpracování pohlaví
        sex_val = r["sex"]
        if sex_val:
            sex_clean = sex_val.strip().upper()
            if sex_clean in ["M", "MUŽ", "MUZ"]:
                pocet_muzu += 1
            elif sex_clean in ["F", "ŽENA", "ZENA"]:
                pocet_zen += 1

        # NOVÉ: Zpracování data vyšetření (očekáváme formát DD.MM.YYYY, jak jej ukládá dicom_logic.py)
        date_val = r["study_date"]
        if date_val and date_val != "N/A" and date_val != "---":
            try:
                # Převedeme řetězec na datetime objekt pro bezpečné porovnávání
                date_obj = datetime.strptime(date_val.strip(), "%d.%m.%Y")
                data_vysetreni.append(date_obj)
            except ValueError:
                pass  # Pokud nelze převést (např. chybný formát), ignorujeme

    if not hodnoty_kap and not hodnoty_hmotnost:
        return (
            jsonify(
                {
                    "status": "error",
                    "zprava": "Vybrané snímky neobsahují validní data pro KAP ani hmotnost.",
                }
            ),
            400,
        )

    statistiky = {}
    kategorie_js = None
    datum_js = None

    if hodnoty_hmotnost:
        statistiky["hmotnost_pocet"] = len(hodnoty_hmotnost)
        statistiky["hmotnost_prumer"] = round(
            sum(hodnoty_hmotnost) / len(hodnoty_hmotnost), 2
        )
        statistiky["hmotnost_max"] = round(max(hodnoty_hmotnost), 2)
        statistiky["hmotnost_min"] = round(min(hodnoty_hmotnost), 2)
    else:
        statistiky["hmotnost_pocet"] = 0
        statistiky["hmotnost_prumer"] = statistiky["hmotnost_max"] = statistiky[
            "hmotnost_min"
        ] = "N/A"

    if hodnoty_kap:
        prumer_kap = round(sum(hodnoty_kap) / len(hodnoty_kap), 2)
        pocet_snimku = len(hodnoty_kap)
        statistiky["pocet"] = pocet_snimku
        statistiky["prumer"] = prumer_kap
        statistiky["max"] = max(hodnoty_kap)
        statistiky["min"] = min(hodnoty_kap)

        hm_min = (
            statistiky["hmotnost_min"] if statistiky["hmotnost_min"] != "N/A" else None
        )
        hm_max = (
            statistiky["hmotnost_max"] if statistiky["hmotnost_max"] != "N/A" else None
        )
        hm_prum = (
            statistiky["hmotnost_prumer"]
            if statistiky["hmotnost_prumer"] != "N/A"
            else None
        )

        # NOVÉ: Nalezení nejstaršího a nejnovějšího vyšetření
        nejstarsi_datum_str = None
        nejnovejsi_datum_str = None
        if data_vysetreni:
            nejstarsi_datum_str = min(data_vysetreni).strftime("%d.%m.%Y")
            nejnovejsi_datum_str = max(data_vysetreni).strftime("%d.%m.%Y")

        conn_db = sqlite3.connect(db_path)
        cursor_db = conn_db.cursor()
        cursor_db.execute("SELECT kategorie FROM dicom_snimky WHERE id = ?", (ids[0],))
        kat_row = cursor_db.fetchone()

        if kat_row and kat_row[0] != "vse":
            kategorie_snimku = kat_row[0]
            ted_db = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ted_zobrazeni = datetime.now().strftime("%d.%m.%Y")

            cursor_db.execute(
                "SELECT id FROM typicke_hodnoty WHERE uzivatel_id = ? AND kategorie = ?",
                (session.get("user_id"), kategorie_snimku),
            )

            # ZMĚNA: Uložení nových sloupců nejstarsi_vysetreni a nejnovejsi_vysetreni
            if cursor_db.fetchone():
                cursor_db.execute(
                    """
                    UPDATE typicke_hodnoty 
                    SET prumerny_kap = ?, pocet_snimku = ?, min_hmotnost = ?, max_hmotnost = ?, prumerna_hmotnost = ?, pocet_zen = ?, pocet_muzu = ?, nejstarsi_vysetreni = ?, nejnovejsi_vysetreni = ?, datum_aktualizace = ? 
                    WHERE uzivatel_id = ? AND kategorie = ?
                """,
                    (
                        prumer_kap,
                        pocet_snimku,
                        hm_min,
                        hm_max,
                        hm_prum,
                        pocet_zen,
                        pocet_muzu,
                        nejstarsi_datum_str,
                        nejnovejsi_datum_str,
                        ted_db,
                        session.get("user_id"),
                        kategorie_snimku,
                    ),
                )
            else:
                cursor_db.execute(
                    """
                    INSERT INTO typicke_hodnoty 
                    (uzivatel_id, kategorie, prumerny_kap, pocet_snimku, min_hmotnost, max_hmotnost, prumerna_hmotnost, pocet_zen, pocet_muzu, nejstarsi_vysetreni, nejnovejsi_vysetreni, datum_aktualizace) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        session.get("user_id"),
                        kategorie_snimku,
                        prumer_kap,
                        pocet_snimku,
                        hm_min,
                        hm_max,
                        hm_prum,
                        pocet_zen,
                        pocet_muzu,
                        nejstarsi_datum_str,
                        nejnovejsi_datum_str,
                        ted_db,
                    ),
                )

            conn_db.commit()
            kategorie_js = kategorie_snimku
            datum_js = ted_zobrazeni

        conn_db.close()
    else:
        statistiky["pocet"] = 0
        statistiky["prumer"] = statistiky["max"] = statistiky["min"] = "N/A"

    return jsonify(
        {
            "status": "success",
            "data": statistiky,
            "kategorie_js": kategorie_js,
            "datum_js": datum_js,
        }
    )


# --- API PRO EXPORT TYPICKÝCH HODNOT DO CSV ---
@app.route("/export-typicke-hodnoty")
def export_typicke_hodnoty():
    if not session.get("user_id"):
        return redirect(url_for("prihlaseni"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        # ZMĚNA: Načtení nejstarsi_vysetreni a nejnovejsi_vysetreni
        cursor.execute(
            """
            SELECT kategorie, prumerny_kap, pocet_snimku, min_hmotnost, max_hmotnost, prumerna_hmotnost, pocet_zen, pocet_muzu, nejstarsi_vysetreni, nejnovejsi_vysetreni, datum_aktualizace 
            FROM typicke_hodnoty 
            WHERE uzivatel_id = ?
        """,
            (session.get("user_id"),),
        )
        radky = cursor.fetchall()

    nazvy_kategorii = {
        "hrudnik_ap": "Hrudník PA/AP",
        "hrudnik_lat": "Hrudník LAT",
        "lebka_ap": "Lebka PA/AP",
        "lebka_lat": "Lebka LAT",
        "c_pater_ap": "Krční páteř AP",
        "c_pater_lat": "Krční páteř LAT",
        "th_pater_ap": "Hrudní páteř AP",
        "th_pater_lat": "Hrudní páteř LAT",
        "ls_pater_ap": "Bederní páteř AP",
        "ls_pater_lat": "Bederní páteř LAT",
        "bricho_ap": "Břicho AP",
        "panev_ap": "Pánev AP",
    }

    si = StringIO()
    si.write("\ufeff")
    writer = csv.writer(si, delimiter=";")

    # ZMĚNA: Přidány dva sloupce do hlavičky CSV
    writer.writerow(
        [
            "Snímaná oblast",
            "Typická hodnota KAP",
            "Počet snímků",
            "Minimální hmotnost",
            "Maximální hmotnost",
            "Průměrná hmotnost",
            "Počet žen",
            "Počet mužů",
            "Nejstarší vyšetření",
            "Nejnovější vyšetření",
            "Datum aktualizace",
        ]
    )

    def formatuj_cislo(val):
        return str(val).replace(".", ",") if val is not None else "N/A"

    for r in radky:
        kategorie_db = r["kategorie"]
        nazev = nazvy_kategorii.get(kategorie_db, kategorie_db)

        datum_db = r["datum_aktualizace"]
        try:
            datum_obj = datetime.strptime(datum_db, "%Y-%m-%d %H:%M:%S")
            datum_hezkym = datum_obj.strftime("%d.%m.%Y")
        except (TypeError, ValueError):
            datum_hezkym = datum_db

        hodnota_kap = formatuj_cislo(r["prumerny_kap"])
        pocet = r["pocet_snimku"] if r["pocet_snimku"] is not None else "0"
        min_hm = formatuj_cislo(r["min_hmotnost"])
        max_hm = formatuj_cislo(r["max_hmotnost"])
        prum_hm = formatuj_cislo(r["prumerna_hmotnost"])

        p_zen = r["pocet_zen"] if r["pocet_zen"] is not None else "0"
        p_muzu = r["pocet_muzu"] if r["pocet_muzu"] is not None else "0"

        # ZMĚNA: Načtení dat vyšetření
        nejstarsi = r["nejstarsi_vysetreni"] if r["nejstarsi_vysetreni"] else "N/A"
        nejnovejsi = r["nejnovejsi_vysetreni"] if r["nejnovejsi_vysetreni"] else "N/A"

        # ZMĚNA: Zápis do řádku ve správném pořadí
        writer.writerow(
            [
                nazev,
                hodnota_kap,
                pocet,
                min_hm,
                max_hm,
                prum_hm,
                p_zen,
                p_muzu,
                nejstarsi,
                nejnovejsi,
                datum_hezkym,
            ]
        )

    output = Response(si.getvalue(), mimetype="text/csv; charset=utf-8")
    output.headers["Content-Disposition"] = (
        "attachment; filename=typicke_hodnoty_KAP.csv"
    )

    return output


# --- API ROUTA PRO SMAZÁNÍ DICOMU (AJAX) ---
@app.route("/api/smazat-dicom/<int:dicom_id>", methods=["DELETE"])
def api_smazat_dicom(dicom_id):
    uzivatel_id = session.get("user_id")
    if not uzivatel_id:
        return jsonify({"status": "error", "zprava": "Neautorizováno! 🔒"}), 401

    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT cesta_k_souboru, thumb_cesta FROM dicom_snimky WHERE id = ? AND uzivatel_id = ?",
                (dicom_id, uzivatel_id),
            )
            vysledek = cursor.fetchone()

            if vysledek:
                raw_cesta = os.path.join(DICOM_RAW_FOLDER, vysledek[0])
                thumb_cesta = os.path.join(DICOM_THUMB_FOLDER, vysledek[1])

                # Smažeme fyzické soubory (originál i náhled)
                if os.path.exists(raw_cesta):
                    os.remove(raw_cesta)
                if os.path.exists(thumb_cesta):
                    os.remove(thumb_cesta)

                # Smažeme z DB
                cursor.execute(
                    "DELETE FROM dicom_snimky WHERE id = ? AND uzivatel_id = ?",
                    (dicom_id, uzivatel_id),
                )
                conn.commit()
                return jsonify(
                    {"status": "success", "zprava": "DICOM byl úspěšně smazán. 🗑️"}
                )

            return jsonify({"status": "error", "zprava": "Soubor nenalezen."}), 404

    except Exception as e:
        return jsonify({"status": "error", "zprava": f"Chyba: {e}"}), 500


# --- ROUTA PRO STAŽENÍ PŮVODNÍHO DICOM SOUBORU ---
@app.route("/stahnout-dicom/<int:dicom_id>")
def stahnout_dicom(dicom_id):
    # 1. Kontrola, zda je uživatel přihlášen
    uzivatel_id = session.get("user_id")
    if not uzivatel_id:
        flash("Pro stahování souborů se musíte přihlásit. 🔒")
        return redirect(url_for("prihlaseni"))

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT cesta_k_souboru, nazev_souboru FROM dicom_snimky WHERE id = ? AND uzivatel_id = ?",
            (dicom_id, uzivatel_id),
        )
        vysledek = cursor.fetchone()

    # 3. Pokud záznam existuje, pošleme soubor uživateli
    if vysledek:
        unikatni_cesta = vysledek[
            0
        ]  # Ten dlouhý název s čísly a hashem, jak to leží na disku
        puvodni_nazev = vysledek[1]  # Původní čistý název, jak ho uživatel nahrál

        # as_attachment=True říká prohlížeči, ať soubor stáhne a neotvírá ho
        # download_name zajistí, že se soubor stáhne pod původním hezkým názvem!
        return send_from_directory(
            DICOM_RAW_FOLDER,
            unikatni_cesta,
            as_attachment=True,
            download_name=puvodni_nazev,
        )

    # Pokud se někdo pokusí stáhnout soubor, který neexistuje nebo není jeho
    flash("Soubor nenalezen nebo k němu nemáte přístup. 🚫")
    return redirect(url_for("muj_dicom"))


# --- API ROUTA PRO ODHLÁŠENÍ (AJAX) ---
@app.route("/api/odhlaseni", methods=["POST"])
def api_odhlaseni():
    # Bezpečně vymaže všechny údaje ze session při odhlášení
    session.clear()

    # Vrátíme JSON s přesměrováním
    return (
        jsonify(
            {
                "status": "success",
                "zprava": "Byli jste úspěšně odhlášeni.",
                "redirect": url_for("index"),
            }
        ),
        200,
    )


if __name__ == "__main__":
    app.run(
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "5000")),
        debug=False,
        use_reloader=False,
    )
