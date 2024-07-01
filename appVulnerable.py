from flask import Flask, request, render_template, flash
import psycopg2

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Necesario para mostrar mensajes flash


def get_db_connection():
    conn = psycopg2.connect(
        dbname="ejemplodb",
        user="postgres",
        password="esteban",
        host="localhost"
    )
    return conn


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Consulta vulnerable
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            cur.execute(query)
            user = cur.fetchone()
        except psycopg2.Error as e:
            flash(f"Database error: {e}")
            user = None
        finally:
            cur.close()
            conn.close()

        if user:
            return f"Welcome, {user[1]}!"
        else:
            flash("Invalid credentials")

    return render_template('login.html')


# Endpoint vulnerable a Error-based SQLi
@app.route('/user_info', methods=['GET'])
def user_info():
    user_id = request.args.get('id')

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Consulta vulnerable a Error-based SQLi
        query = f"SELECT username, password FROM users WHERE id = {user_id}"
        cur.execute(query)
        user = cur.fetchone()
    except psycopg2.Error as e:
        return f"Database error: {e}"
    finally:
        cur.close()
        conn.close()

    if user:
        return f"Data del usuario"
    else:
        return "No user found"


# Endpoint vulnerable a Union-based SQLi
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Consulta vulnerable a Union-based SQLi
        query = f"SELECT id, username FROM users WHERE username LIKE '%{query}%'"
        cur.execute(query)
        results = cur.fetchall()
    except psycopg2.Error as e:
        return f"Database error: {e}"
    finally:
        cur.close()
        conn.close()

    if results:
        return '<br>'.join([f"ID: {row[0]}, Username: {row[1]}" for row in results])
    else:
        return "No results found"


# Endpoint vulnerable a Inferential SQLi (Time-based Blind SQLi)
@app.route('/is_admin', methods=['GET'])
def is_admin():
    username = request.args.get('username')

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Consulta vulnerable a Time-based Blind SQLi
        query = f"SELECT 1 FROM users WHERE username = '{username}'; SELECT pg_sleep(5);"
        cur.execute(query)
        result = cur.fetchone()
    except psycopg2.Error as e:
        return f"Database error: {e}"
    finally:
        cur.close()
        conn.close()

    return "Query executed"


# Endpoint vulnerable a Boolean-based Blind SQLi
@app.route('/exists', methods=['GET'])
def exists():
    username = request.args.get('username')

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Consulta vulnerable a Boolean-based Blind SQLi
        query = f"SELECT 1 FROM users WHERE username = '{username}'"
        cur.execute(query)
        result = cur.fetchone()
    except psycopg2.Error as e:
        return f"Database error: {e}"
    finally:
        cur.close()
        conn.close()

    if result:
        return "User exists"
    else:
        return "User does not exist"


if __name__ == '__main__':
    app.run(debug=True)
