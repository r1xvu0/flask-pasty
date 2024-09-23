from flask import Flask, request, redirect, render_template, url_for, jsonify, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from markupsafe import Markup
import bleach
from bleach_allowlist import markdown_tags, markdown_attrs
import psycopg2
from psycopg2.extras import DictCursor
from werkzeug.security import generate_password_hash, check_password_hash
import os
import string
import random
import markdown
from markdown.extensions import codehilite, fenced_code, tables, attr_list

extra_tags = ['span', 'pre', 'code', 'div']
extra_attrs = {
    'span': ['class'],
    'pre': ['class'],
    'code': ['class'],
    'div': ['class'],
}

# Combine the existing markdown tags and attributes with the extra ones for Pygments
final_tags = list(set(markdown_tags + extra_tags))
final_attrs = {**markdown_attrs, **extra_attrs}

def markdown_filter(text):
    extensions = [
        'fenced_code',
        'codehilite',
        'tables',
        'attr_list',
        'def_list',
        'abbr',
        'footnotes',
        'md_in_html',
        'nl2br',
        'sane_lists',
    ]
    md = markdown.Markdown(extensions=extensions)
    html = md.convert(text)

    # print("Before sanitization:", html)  # Debugging: Output the HTML before sanitization

    # Sanitize the HTML but allow Pygments' tags and attributes
    clean_html = bleach.clean(html, tags=final_tags, attributes=final_attrs)
    
    # print("After sanitization:", clean_html)  # Debugging: Output the HTML after sanitization

    return Markup(clean_html)

app = Flask(__name__)
app.jinja_env.filters['markdown'] = markdown_filter
app.secret_key = 'supersecretkey'  # Change this to a real secret key in production

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://pasty_owner:SB7dRzJr5aQO@ep-ancient-cake-a2au5gcb.eu-central-1.aws.neon.tech/pasty?sslmode=require')

def get_db():
    conn = psycopg2.connect(DATABASE_URL, sslmode='require', cursor_factory=DictCursor)
    return conn

def create_tables():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute('''CREATE TABLE IF NOT EXISTS users (
                               id SERIAL PRIMARY KEY,
                               username VARCHAR(255) UNIQUE NOT NULL,
                               password_hash TEXT NOT NULL);''')
            # cur.execute('''CREATE TABLE IF NOT EXISTS entries (
            #                    id SERIAL PRIMARY KEY,
            #                    title VARCHAR(255) NOT NULL,
            #                    content TEXT NOT NULL,
            #                    user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
            #                    public BOOLEAN NOT NULL DEFAULT FALSE);''')
            cur.execute('''CREATE TABLE IF NOT EXISTS entries (
                               id SERIAL PRIMARY KEY,
                               title VARCHAR(255) NOT NULL,
                               content TEXT NOT NULL,
                               user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
                               public BOOLEAN NOT NULL DEFAULT FALSE,
                               custom_url VARCHAR(255) UNIQUE);''')
            cur.execute('''CREATE TABLE IF NOT EXISTS collaborators (
                               id SERIAL PRIMARY KEY,
                               entry_id INTEGER REFERENCES entries (id) ON DELETE CASCADE,
                               user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
                               UNIQUE (entry_id, user_id));''')
            conn.commit()

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if user:
                return User(id=user['id'], username=user['username'], password_hash=user['password_hash'])
    return None

@app.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template('landing.html')

@app.route('/home')
@login_required
def index():
    user_id = current_user.id
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT e.id, e.title, e.public, e.custom_url, 
                       CASE WHEN e.user_id = %s THEN true ELSE false END AS is_owner
                FROM entries e
                LEFT JOIN collaborators c ON e.id = c.entry_id
                WHERE e.user_id = %s OR c.user_id = %s
                ORDER BY e.id DESC
            """, (user_id, user_id, user_id))
            entries = cur.fetchall()
    return render_template('index.html', entries=entries)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        
        with get_db() as conn:
            with conn.cursor() as cur:
                try:
                    cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash))
                    conn.commit()
                    flash('Registration successful! You can now log in.', 'success')
                    return redirect(url_for('login'))
                except psycopg2.IntegrityError:
                    conn.rollback()
                    flash('Username already exists!', 'danger')
                    return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cur.fetchone()
                if user and check_password_hash(user['password_hash'], password):
                    user_obj = User(id=user['id'], username=user['username'], password_hash=user['password_hash'])
                    login_user(user_obj)
                    flash('Logged in successfully!', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('landing'))

def generate_random_identifier(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

@app.route('/editor', methods=['GET', 'POST'])
@login_required
def editor():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        public = 'public' in request.form
        custom_url = request.form.get('custom_url', '').strip()
        user_id = current_user.id
        
        if not custom_url:
            custom_url = generate_random_identifier()
        
        with get_db() as conn:
            with conn.cursor() as cur:
                try:
                    cur.execute("INSERT INTO entries (title, content, user_id, public, custom_url) VALUES (%s, %s, %s, %s, %s)", 
                                (title, content, user_id, public, custom_url))
                    conn.commit()
                    flash('Entry saved successfully!', 'success')
                    return redirect(url_for('view_entry', custom_url=custom_url))
                except psycopg2.IntegrityError:
                    conn.rollback()
                    flash('Custom URL already exists. Please choose a different one.', 'danger')
                    return render_template('editor.html', title=title, content=content, public=public, custom_url=custom_url)
    
    return render_template('editor.html')

@app.route('/preview', methods=['POST'])
@login_required
def preview():
    content = request.form['content']
    html_content = markdown_filter(content)
    return html_content

@app.route('/explore')
def explore():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT e.id, e.title, e.custom_url, u.username 
                FROM entries e 
                JOIN users u ON e.user_id = u.id 
                WHERE e.public = TRUE 
                ORDER BY e.id DESC
            """)
            public_entries = cur.fetchall()
    return render_template('explore.html', public_entries=public_entries)

@app.route('/entry/<custom_url>')
def view_entry(custom_url):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT e.*, u.username, 
                       (SELECT COUNT(*) FROM collaborators c WHERE c.entry_id = e.id AND c.user_id = %s) > 0 AS is_collaborator
                FROM entries e 
                JOIN users u ON e.user_id = u.id 
                WHERE e.custom_url = %s
            """, (current_user.id if current_user.is_authenticated else None, custom_url))
            entry = cur.fetchone()
    
    if entry:
        if entry['public'] or (current_user.is_authenticated and (entry['user_id'] == current_user.id or entry['is_collaborator'])):
            return render_template('view_entry.html', entry=entry)
        else:
            flash('You do not have permission to view this entry', 'danger')
            return redirect(url_for('index'))
    else:
        flash('Entry not found', 'danger')
        return redirect(url_for('index'))

@app.route('/edit/<custom_url>', methods=['GET', 'POST'])
@login_required
def edit_entry(custom_url):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT e.*, 
                       (SELECT COUNT(*) FROM collaborators c WHERE c.entry_id = e.id AND c.user_id = %s) > 0 AS is_collaborator
                FROM entries e 
                WHERE e.custom_url = %s
            """, (current_user.id, custom_url))
            entry = cur.fetchone()
    
    if not entry or (entry['user_id'] != current_user.id and not entry['is_collaborator']):
        flash('You do not have permission to edit this entry', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        public = 'public' in request.form
        new_custom_url = request.form.get('custom_url', '').strip()
        
        if not new_custom_url:
            new_custom_url = generate_random_identifier()
        
        with get_db() as conn:
            with conn.cursor() as cur:
                try:
                    cur.execute("UPDATE entries SET title = %s, content = %s, public = %s, custom_url = %s WHERE id = %s", 
                                (title, content, public, new_custom_url, entry['id']))
                    conn.commit()
                    flash('Entry updated successfully!', 'success')
                    return redirect(url_for('view_entry', custom_url=new_custom_url))
                except psycopg2.IntegrityError:
                    conn.rollback()
                    flash('Custom URL already exists. Please choose a different one.', 'danger')
                    return render_template('editor.html', entry=entry, custom_url=new_custom_url)
    
    return render_template('editor.html', entry=entry)

@app.route('/delete/<custom_url>', methods=['POST'])
@login_required
def delete_entry(custom_url):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM entries WHERE custom_url = %s AND user_id = %s", (custom_url, current_user.id))
            conn.commit()
    flash('Entry deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/toggle_visibility/<custom_url>', methods=['POST'])
@login_required
def toggle_visibility(custom_url):
    with get_db() as conn:
        with conn.cursor() as cur:
            # First, check if the entry belongs to the current user
            cur.execute("SELECT public FROM entries WHERE custom_url = %s AND user_id = %s", (custom_url, current_user.id))
            entry = cur.fetchone()
            if entry is None:
                return "Entry not found or you don't have permission", 404

            # Toggle the public status
            new_status = not entry['public']
            cur.execute("UPDATE entries SET public = %s WHERE custom_url = %s", (new_status, custom_url))
            conn.commit()

            # Fetch the updated entry
            cur.execute("SELECT id, title, public, custom_url FROM entries WHERE custom_url = %s", (custom_url,))
            updated_entry = cur.fetchone()

    # Return the updated list item HTML
    return render_template('_entry_list_item.html', entry=updated_entry)

@app.route('/collaborators/<custom_url>', methods=['GET', 'POST'])
@login_required
def manage_collaborators(custom_url):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM entries WHERE custom_url = %s AND user_id = %s", (custom_url, current_user.id))
            entry = cur.fetchone()
    
    if not entry:
        flash('You do not have permission to manage collaborators for this entry', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        collaborator_username = request.form['collaborator']
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE username = %s", (collaborator_username,))
                collaborator = cur.fetchone()
                if collaborator:
                    try:
                        cur.execute("INSERT INTO collaborators (entry_id, user_id) VALUES (%s, %s)", 
                                    (entry['id'], collaborator['id']))
                        conn.commit()
                        flash(f'Added {collaborator_username} as a collaborator', 'success')
                    except psycopg2.IntegrityError:
                        conn.rollback()
                        flash(f'{collaborator_username} is already a collaborator', 'warning')
                else:
                    flash(f'User {collaborator_username} not found', 'danger')
    
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.username 
                FROM collaborators c 
                JOIN users u ON c.user_id = u.id 
                WHERE c.entry_id = %s
            """, (entry['id'],))
            collaborators = [row['username'] for row in cur.fetchall()]
    
    return render_template('manage_collaborators.html', entry=entry, collaborators=collaborators)

@app.route('/remove_collaborator/<custom_url>/<string:username>', methods=['POST'])
@login_required
def remove_collaborator(custom_url, username):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM entries WHERE custom_url = %s AND user_id = %s", (custom_url, current_user.id))
            entry = cur.fetchone()
    
    if not entry:
        flash('You do not have permission to manage collaborators for this entry', 'danger')
        return redirect(url_for('index'))
    
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM collaborators 
                WHERE entry_id = %s AND user_id = (SELECT id FROM users WHERE username = %s)
            """, (entry['id'], username))
            conn.commit()
    
    flash(f'Removed {username} from collaborators', 'success')
    return redirect(url_for('manage_collaborators', custom_url=custom_url))

@login_manager.unauthorized_handler
def unauthorized():
    flash('You must be logged in to access this page.', 'warning')
    return redirect(url_for('landing'))

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)