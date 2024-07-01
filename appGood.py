from flask import Flask, request, render_template, flash
import psycopg2
from psycopg2 import sql, OperationalError

app = Flask(__name__)
app.secret_key = 'supersecretkey'


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
            # Consulta segura usando consultas parametrizadas
            query = sql.SQL("SELECT * FROM users WHERE username = %s AND password = %s")
            cur.execute(query, (username, password))
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


@app.route('/user_info', methods=['GET'])
def user_info():
    user_id = request.args.get('id')

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Consulta segura usando consultas parametrizadas
        query = sql.SQL("SELECT username, password FROM users WHERE id = %s")
        cur.execute(query, (user_id,))
        user = cur.fetchone()
    except psycopg2.Error as e:
        return "Database error."
    finally:
        cur.close()
        conn.close()

    if user:
        return f"Data del usuario"
    else:
        return "No user found"


# Endpoint protegido contra Union-based SQLi
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Consulta segura usando consultas parametrizadas
        sql_query = sql.SQL("SELECT id, username FROM users WHERE username LIKE %s")
        cur.execute(sql_query, (f"%{query}%",))
        results = cur.fetchall()
    except psycopg2.Error as e:
        return "Database error."
    finally:
        cur.close()
        conn.close()

    if results:
        return '<br>'.join([f"ID: {row[0]}, Username: {row[1]}" for row in results])
    else:
        return "No results found"


@app.route('/is_admin', methods=['GET'])
def is_admin():
    username = request.args.get('username')

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Establecer un límite de tiempo para las consultas
        cur.execute("SET statement_timeout = 2000")  # 2000 ms = 2 segundos

        # Consulta vulnerable a Time-based Blind SQLi
        query = f"SELECT 1 FROM users WHERE username = '{username}'; SELECT pg_sleep(5);"
        cur.execute(query)
        result = cur.fetchone()
    except OperationalError as e:
        if 'statement timeout' in str(e):
            return "Query timed out."
        else:
            return "Database error."
    except psycopg2.Error as e:
        return "Database error."
    finally:
        cur.close()
        conn.close()

    if result:
        return "Query executed successfully"
    else:
        return "No such user"


# Endpoint protegido contra Boolean-based Blind SQLi
@app.route('/exists', methods=['GET'])
def exists():
    username = request.args.get('username')

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Consulta segura usando consultas parametrizadas
        query = sql.SQL("SELECT 1 FROM users WHERE username = %s")
        cur.execute(query, (username,))
        result = cur.fetchone()
    except psycopg2.Error as e:
        return "Database error."
    finally:
        cur.close()
        conn.close()

    if result:
        return "User exists"
    else:
        return "User does not exist"


if __name__ == '__main__':
    app.run(debug=True)
