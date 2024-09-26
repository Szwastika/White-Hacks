from flask import Flask, render_template, request, redirect, url_for, flash, session,jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import requests
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key
GEMINI_API_KEY = "AIzaSyB38okcsBEWiHvYmd2Bj-0ZN1Vu4VqB6oc"

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL)')
    conn.close()

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('medint'))
    return redirect(url_for('login'))

@app.route('/medint')
def medint():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('medint.html')

@app.route('/hospitalsuggestions')
def hospital_suggestions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('hospitalsuggestions.html')

@app.route('/create-account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email)).fetchone()
        
        if user:
            flash('Username or email already exists')
        else:
            hashed_password = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, hashed_password))
            conn.commit()
            flash('Account created successfully')
            conn.close()
            return redirect(url_for('medint'))
        
        conn.close()
    
    return render_template('create_account.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully')
            return redirect(url_for('medint'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('home'))
@app.route('/analyze_symptoms', methods=['POST'])
def analyze_symptoms():
    symptoms = request.json.get('symptoms')
    
    prompt = f"""Analyze the following symptoms and provide a diagnosis, recommendation, and medication if applicable ( NO explanation just one word answer ). If it's a simple disease like fever, cold, or pain, suggest over-the-counter medication. For more serious conditions, recommend consulting a doctor. Respond in JSON format:
    {{
        "diagnosis": "",
        "recommendation": "",
        "medication": ""
    }}
    
    Symptoms: {symptoms}"""

    try:
        response = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={GEMINI_API_KEY}",
            json={
                "contents": [{"parts": [{"text": prompt}]}]
            },
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        ai_response = response.json()['candidates'][0]['content']['parts'][0]['text']
        return jsonify(ai_response)
    except Exception as e:
        print(f"Error calling Gemini API: {str(e)}")
        return jsonify({"error": "An error occurred while analyzing symptoms. Please try again."}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True)