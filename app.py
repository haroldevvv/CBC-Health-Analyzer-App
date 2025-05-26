import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash 

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def get_db_connection():
    connection = sqlite3.connect('hrcbc_app.db')
    connection.row_factory = sqlite3.Row
    return connection

# Initialize SQLite database and create the users table if it doesn't exist
def initialize_db():
    connection = get_db_connection()
    cursor = connection.cursor()

    #Create the users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            age INTEGER NOT NULL,
            sex TEXT NOT NULL,
            weight REAL NOT NULL,
            height REAL NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    ''')

    #Create the cbc_results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cbc_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            hb REAL NOT NULL,
            rbc REAL NOT NULL,
            hct_pcv REAL NOT NULL,
            mcv REAL NOT NULL,
            mch REAL NOT NULL,
            mchc REAL NOT NULL,
            wbc REAL NOT NULL,
            neutrophils REAL NOT NULL,
            lymphocytes REAL NOT NULL,
            platelet REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    connection.commit()
    connection.close()

initialize_db()    
@app.route("/")
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))  # Redirect logged-in users to the dashboard
    return render_template("/login.html")  # Landing page

#App route for registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Handle registration logic
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        age = int(request.form["age"])
        sex = request.form["sex"]
        weight = float(request.form["weight"])
        height = float(request.form["height"])
        email = request.form["email"]
        password = request.form["password"]
        password_hash = generate_password_hash(password)

        # Insert user data into the database
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('''
                INSERT INTO users (first_name, last_name, age, sex, weight, height, email, password_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (first_name, last_name, age, sex, weight, height, email, password_hash))
            connection.commit()
            connection.close()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Error: Email already exists.', 'danger')
        except Exception as e:
            flash(f'Error: Unable to register. {str(e)}', 'danger')

    return render_template('registration.html')

#App route for login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip()
        password = request.form["password"]

        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            connection.close()

            if user:
                print("User found:", user)  # Debug: Check user details
                if check_password_hash(user[8], password):  # Adjust index if necessary
                    print("Password matches!")  # Debug: Password check
                    session['user_id'] = user[0]
                    session['user_name'] = f"{user[1]} {user[2]}"
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    print("Password does not match.")  # Debug: Mismatch
            else:
                print("User not found for email:", email)  # Debug: No user found

            flash('Invalid email or password.', 'danger')
        except Exception as e:
            print("Error during login:", e)  # Debug: Log exceptions
            flash(f"Error: {str(e)}", 'danger')

    return render_template('login.html')

#App route for dashboard
@app.route("/dashboard")
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    
    user_first_name = session.get('user_name', 'User').split()[0]
    return render_template("dashboard.html", user_first_name=user_first_name)

#App route for cbc analysis
@app.route("/cbc_analysis")
def cbc_analysis():
    if 'user_id' not in session:
        flash('Please log in to access this feature.', 'warning')
        return redirect(url_for('login'))

    # Fetch CBC analysis data from the database for the logged-in user
    user_id = session['user_id']
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM cbc_results WHERE user_id = ?", (user_id,))
    rows = cursor.fetchall()
    connection.close()

    # Process results 
    results = []
    for row in rows:
        results.append({
            'hb': row['hb'],
            'rbc': row['rbc'],
            'hct_pcv': row['hct_pcv'],
            'mcv': row['mcv'],
            'mch': row['mch'],
            'mchc': row['mchc'],
            'wbc': row['wbc'],
            'neutrophils': row['neutrophils'],
            'lymphocytes': row['lymphocytes'],
            'platelet': row['platelet'],
        })

    return render_template("cbc_analysis.html", results=results)


#Reference ranges for CBC parameters
REFERENCE_RANGES = {
    'hb': (11.5, 16.5),  # Hemoglobin
    'rbc': (3.5, 5.5),   # Red Blood Cell count
    'hct_pcv': (35.0, 55.0), # Hematocrit
    'mcv': (75.0, 100.0),# Mean Corpuscular Volume
    'mch': (25.0, 35.0), # Mean Corpuscular Hemoglobin
    'mchc': (31.0, 38.0),# Mean Corpuscular Hemoglobin Concentration
    'wbc': (3.5, 10.0),  # White Blood Cell count
    'neutrophils': (0.4, 0.6), #Neutrophils count
    'lymphocytes': (0.9, 5.0), #Lymphocytes count 
    'platelet': (130, 400), # Platelet count
}

def evaluate_cbc(parameter, value):
    """Determine if a value is LOW, NORMAL, or HIGH based on reference ranges."""
    low, high = REFERENCE_RANGES.get(parameter, (None, None))
    if low is None or high is None:
        return "UNKNOWN"
    if value < low:
        return "LOW"
    elif value > high:
        return "HIGH"
    else:
        return "NORMAL"

def get_user_cbc_results(user_id):
    """Fetch CBC results for a specific user from the database."""
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM cbc_results WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,))
    row = cursor.fetchone()
    connection.close()

    if row:
        return {
            'hb': row['hb'],
            'rbc': row['rbc'],
            'hct_pcv': row['hct_pcv'],
            'mcv': row['mcv'],
            'mch': row['mch'],
            'mchc': row['mchc'],
            'wbc': row['wbc'],
            'neutrophils': row['neutrophils'],
            'lymphocytes': row['lymphocytes'],
            'platelet': row['platelet']
        }
    return None

#App route for health tips
@app.route("/health_tips")
def health_tips():
    if 'user_id' not in session:
        flash('Please log in to access this feature.', 'warning')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    cbc_results = get_user_cbc_results(user_id)

    if not cbc_results:
        flash('No CBC results found. Please submit your data.', 'info')
        return redirect(url_for('dashboard')) 
    
    # Analyze CBC results
    cbc_analysis = {
        param: evaluate_cbc(param, value)
        for param, value in cbc_results.items()
    }

# Define specific health tips for each parameter and status
    health_tips_mapping = {
        "HB": {
            "LOW": "It could indicate iron deficiency. Consider incorporating iron-rich foods into your diet.",
            "HIGH": "It might indicate polycythemia or other conditions. A doctor’s evaluation is recommended."
        },
        "RBC": {
            "LOW": "Low RBC count might indicate anemia, malnutrition, or being fatigue. Consult your doctor.",
            "HIGH": "High RBC count might be linked to dehydration, polycythemia, or other conditions. Further tests are advised."
        },
        "HCT_PCV": {
            "LOW": "Low hematocrit count might indicate vitamin or mineral deficiency, being fatigue, and anemia. Please consult your doctor.",
            "HIGH": "High hematocrit count might indicate dehydration, headaches, or other conditions. Stay hydrated and consult a doctor."
        },
        "MCV": {
            "LOW": "Low MCV might suggest an iron deficiency anemia and other hemoglobin disorders. Consider consulting a hematologist.",
            "HIGH": "High MCV could indicate low vitamin B12 level, folate deficiency, or other conditions. Discuss with a healthcare professional."
        },
        "MCH": {
            "LOW": "Low MCH might indicate the presence of iron deficiency anemia. Check your iron levels.",
            "HIGH": "High MCH might indicate being fatigue, having a very pale skin, or other conditions. Consult a doctor."
        },
        "MCHC": {
            "LOW": "Low MCHC might indicate chronic blood loss or iron-deficiency anemia. Seek medical advice.",
            "HIGH": "High MCHC might indicate weight loss, palpitations, and being fatigue. Consult your doctor immediately."
        },
        "WBC": {
            "LOW": "Low WBC might suggest a weakened immune system. Seek medical advice promptly.",
            "HIGH": "High WBC could indicate an infection or inflammation. Consult a healthcare professional."
        },
        "NEUTROPHILS": {
            "LOW": "Low neutrophils might indicate having fever, sore throat, and other conditions. Consult a doctor.",
            "HIGH": "High neutrophils could suggest a recent or ongoing infection, acute infection, or injury. A doctor's evaluation is recommended."
        },
        "LYMPHOCYTES": {
            "LOW": "Low lymphocytes might suggest unusual infections, frequent colds, or pneumonia. Consult your doctor immediately",
            "HIGH": "High lymphocytes could indicate viral and bacterial infections, or autoimmune diseases. Seek medical advice."
        },
        "PLATELET": {
            "LOW": "Low platelet count might indicate excessive bleeding, heavy menstrual periods for women, or bruises. Seek for a medical attention.",
            "HIGH": "High platelet count could suggest immune system problems, anemia, or autoimmune disorders. Consult your doctor right away."
        },
    }

    # Generate health tips based on the parameter status
    health_tips = []
    for param, status in cbc_analysis.items():
        param = param.upper()  # Ensure case consistency
        if param in health_tips_mapping and status in health_tips_mapping[param]:
            health_tips.append(f"{param}: {health_tips_mapping[param][status]}")
        else:
            # Fallback for parameters without specific messages
            health_tips.append(f"{param}: Status is {status}. Further evaluation is recommended.")

    return render_template("health_tips.html", cbc_results=cbc_results, cbc_analysis=cbc_analysis, health_tips=health_tips)

#App route for new cbc analysis
@app.route("/new_cbc_analysis", methods=["GET", "POST"])
def new_cbc_analysis():
    if 'user_id' not in session:
        flash('Please log in to access this feature.', 'warning')
        return redirect(url_for('login'))
    if request.method == "POST":
        # Logic to handle new CBC data input
        user_id = session['user_id']
        hb = float(request.form["hb"])
        rbc = float(request.form["rbc"])
        hct_pcv = float(request.form["hct_pcv"])
        mcv = float(request.form["mcv"])
        mch = float(request.form["mch"])
        mchc = float(request.form["mchc"])
        wbc = float(request.form["wbc"])
        neutrophils = float(request.form["neutrophils"])
        lymphocytes = float(request.form["lymphocytes"])
        platelet = float(request.form["platelet"])

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute('''
            INSERT INTO cbc_results (user_id, hb, rbc, hct_pcv, mcv, mch, mchc, wbc, neutrophils, lymphocytes, platelet)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, hb, rbc, hct_pcv, mcv, mch, mchc, wbc, neutrophils, lymphocytes, platelet))
        connection.commit()
        connection.close()
        flash('New CBC analysis submitted successfully!', 'success')
        return redirect(url_for('cbc_analysis'))
    return render_template("new_cbc_analysis.html")

#App route for about
@app.route('/about')
def about():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    return render_template('about.html')  # About page

#App route for features
@app.route('/features')
def features():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    return render_template('features.html')  # Allow access for logged-in users

#App route for logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))
    
if __name__ == "__main__":
    app.run(debug=True)
