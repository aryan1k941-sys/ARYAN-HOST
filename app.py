import os, sqlite3, subprocess, threading, time, signal, sys, re
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get('DATA_DIR', BASE / 'data')).resolve()
UPLOAD_ROOT = DATA / 'uploads'
DB = DATA / 'aryan_host.sqlite3'
DATA.mkdir(parents=True, exist_ok=True)
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-only-change-this-secret-before-deploying'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB per upload
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 24

# Uploaded code is arbitrary code. Keep RUNNER_ENABLED=0 on public deployments until
# execution is moved into real OS/container sandboxes. This is not a security sandbox.
RUNNER_ENABLED = os.environ.get('RUNNER_ENABLED', '0') == '1'
processes = {}  # (username, filename) -> Popen
log_locks = {}
lock = threading.RLock()
ALLOWED_EXTENSIONS = {'.py'}


def db():
    con = sqlite3.connect(DB, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            email TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )''')

init_db()


def user_folder(username):
    # username is validated during registration and loaded from the database.
    path = (UPLOAD_ROOT / username).resolve()
    if UPLOAD_ROOT.resolve() not in path.parents:
        raise ValueError('Invalid user path')
    path.mkdir(parents=True, exist_ok=True)
    return path


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('username'):
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapped


def owned_file(filename):
    safe = secure_filename(filename or '')
    if not safe or safe != filename or Path(safe).suffix.lower() not in ALLOWED_EXTENSIONS:
        abort(400, 'Only Python .py files are supported.')
    path = (user_folder(session['username']) / safe).resolve()
    if path.parent != user_folder(session['username']).resolve():
        abort(400)
    if not path.is_file():
        abort(404)
    return path


def append_log(username, filename, text):
    folder = user_folder(username)
    path = folder / (secure_filename(filename) + '.log')
    with lock:
        lk = log_locks.setdefault((username, filename), threading.Lock())
    with lk:
        with path.open('a', encoding='utf-8', errors='replace') as f:
            f.write(text)
            f.flush()
        # Keep log files bounded.
        try:
            if path.stat().st_size > 300_000:
                data = path.read_text(encoding='utf-8', errors='replace')[-150_000:]
                path.write_text('[Older log output trimmed]\n' + data, encoding='utf-8')
        except OSError:
            pass


def capture_output(key, proc):
    username, filename = key
    try:
        for line in iter(proc.stdout.readline, ''):
            if not line:
                break
            append_log(username, filename, line)
    except Exception as exc:
        append_log(username, filename, f'\n[log reader error] {exc}\n')
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass


@app.get('/')
def index():
    if not session.get('username'):
        return redirect(url_for('login'))
    folder = user_folder(session['username'])
    files = []
    for p in sorted(folder.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
        if p.is_file() and p.suffix.lower() == '.py':
            with lock:
                proc = processes.get((session['username'], p.name))
                running = bool(proc and proc.poll() is None)
            files.append({'name': p.name, 'size': p.stat().st_size, 'running': running})
    return render_template('dashboard.html', username=session['username'], files=files,
                           runner_enabled=RUNNER_ENABLED)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if not re.fullmatch(r'[A-Za-z0-9_-]{3,24}', username):
            flash('Username must be 3–24 characters: letters, numbers, _ or -.', 'error')
        elif not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
            flash('Enter a valid email address.', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
        elif password != confirm:
            flash('Passwords do not match.', 'error')
        else:
            try:
                with db() as con:
                    con.execute('INSERT INTO users(username,email,password_hash) VALUES(?,?,?)',
                                (username, email, generate_password_hash(password)))
                user_folder(username)
                session.clear()
                session.permanent = True
                session['username'] = username
                flash('Account created successfully. Welcome to ARYAN HOST!', 'success')
                return redirect(url_for('index'))
            except sqlite3.IntegrityError:
                flash('That username or email is already registered.', 'error')
    return render_template('auth.html', mode='register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        with db() as con:
            user = con.execute('SELECT username,password_hash FROM users WHERE username = ? COLLATE NOCASE',
                               (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session.permanent = True
            session['username'] = user['username']
            return redirect(url_for('index'))
        flash('Incorrect username or password.', 'error')
    return render_template('auth.html', mode='login')


@app.post('/logout')
@login_required
def logout():
    username = session['username']
    with lock:
        keys = [k for k in processes if k[0] == username]
    for key in keys:
        _stop_process(key)
    session.clear()
    return redirect(url_for('login'))


@app.post('/upload')
@login_required
def upload():
    f = request.files.get('file')
    if not f or not f.filename:
        flash('Choose a .py file to upload.', 'error')
        return redirect(url_for('index'))
    name = secure_filename(f.filename)
    if not name or Path(name).suffix.lower() not in ALLOWED_EXTENSIONS:
        flash('Only .py files are accepted in this starter version.', 'error')
        return redirect(url_for('index'))
    target = user_folder(session['username']) / name
    if target.exists():
        flash('A file with that name already exists. Delete it first or rename the upload.', 'error')
        return redirect(url_for('index'))
    f.save(target)
    (target.parent / (name + '.log')).write_text('Uploaded to ARYAN HOST.\n', encoding='utf-8')
    flash(f'{name} uploaded. Use Start when the runner is enabled.', 'success')
    return redirect(url_for('index'))


def _stop_process(key):
    with lock:
        proc = processes.get(key)
    if not proc or proc.poll() is not None:
        with lock:
            processes.pop(key, None)
        return False
    try:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        append_log(key[0], key[1], '\n[ARYAN HOST] Process stopped.\n')
    except Exception as exc:
        append_log(key[0], key[1], f'\n[ARYAN HOST] Stop error: {exc}\n')
    finally:
        with lock:
            processes.pop(key, None)
    return True


@app.post('/start/<filename>')
@login_required
def start(filename):
    if not RUNNER_ENABLED:
        flash('Bot execution is disabled for safety. Set RUNNER_ENABLED=1 only for a private/trusted deployment.', 'error')
        return redirect(url_for('index'))
    path = owned_file(filename)
    key = (session['username'], path.name)
    with lock:
        existing = processes.get(key)
        if existing and existing.poll() is None:
            flash('This bot is already running.', 'success')
            return redirect(url_for('index'))
    append_log(key[0], key[1], '\n[ARYAN HOST] Starting process...\n')
    try:
        # No shell is used. This is still NOT a sandbox: uploaded Python can access the host.
        proc = subprocess.Popen([sys.executable, '-u', str(path)], cwd=str(path.parent),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, start_new_session=True,
                                env={**os.environ, 'PYTHONUNBUFFERED': '1'})
        with lock:
            processes[key] = proc
        threading.Thread(target=capture_output, args=(key, proc), daemon=True).start()
        flash(f'{path.name} started.', 'success')
    except Exception as exc:
        append_log(key[0], key[1], f'\n[ARYAN HOST] Start failed: {exc}\n')
        flash('Could not start this bot. Check its log.', 'error')
    return redirect(url_for('index'))


@app.post('/stop/<filename>')
@login_required
def stop(filename):
    path = owned_file(filename)
    _stop_process((session['username'], path.name))
    flash(f'{path.name} stopped.', 'success')
    return redirect(url_for('index'))


@app.post('/restart/<filename>')
@login_required
def restart(filename):
    path = owned_file(filename)
    key = (session['username'], path.name)
    if not RUNNER_ENABLED:
        flash('Bot execution is disabled. Set RUNNER_ENABLED=1 only for a private/trusted deployment.', 'error')
        return redirect(url_for('index'))
    _stop_process(key)
    return start(filename)


@app.get('/logs/<filename>')
@login_required
def logs(filename):
    path = owned_file(filename)
    log = path.parent / (path.name + '.log')
    try:
        content = log.read_text(encoding='utf-8', errors='replace')[-20000:]
    except OSError:
        content = 'No logs yet.'
    with lock:
        proc = processes.get((session['username'], path.name))
        running = bool(proc and proc.poll() is None)
    return jsonify({'filename': path.name, 'running': running, 'logs': content})


@app.post('/delete/<filename>')
@login_required
def delete(filename):
    path = owned_file(filename)
    _stop_process((session['username'], path.name))
    path.unlink(missing_ok=True)
    (path.parent / (path.name + '.log')).unlink(missing_ok=True)
    flash(f'{path.name} deleted.', 'success')
    return redirect(url_for('index'))


@app.errorhandler(413)
def too_large(_error):
    flash('File is too large. Maximum upload size is 10 MB.', 'error')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '5000')), debug=False)
