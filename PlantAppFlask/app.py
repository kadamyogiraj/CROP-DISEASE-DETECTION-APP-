from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_cors import CORS
from functools import wraps
import os
import secrets

app = Flask(__name__)
# Security: secret key from environment variable, never hardcoded
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app)

# Security: enforce secure session cookies in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialize database
from database import init_db, create_user, login_user, save_diagnosis, get_diagnosis_history, save_chat, get_diagnosis_stats, get_user_by_email, reset_password
init_db()

# Upload folder for images
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Allowed image extensions for security
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'}

def allowed_file(filename):
    """Check if uploaded file has an allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ===== Authentication Decorator =====
def login_required(f):
    """Decorator to protect routes - requires login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # For API routes, return JSON error
            if request.path.startswith('/api/'):
                return jsonify({"success": False, "error": "Please login first"}), 401
            # For page routes, redirect to login
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ===== Public Routes (no login required) =====

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/login')
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot_password.html')

# ===== Protected Routes (login required) =====

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/diagnosis')
@login_required
def diagnosis():
    return render_template('diagnosis.html')

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

@app.route('/history')
@login_required
def history():
    return render_template('history.html')

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/language')
@login_required
def language():
    """Language selection page"""
    return render_template('language.html')

# ===== API Endpoints =====

@app.route('/api/signup', methods=['POST'])
def api_signup():
    """User signup with database storage"""
    data = request.json
    if not data:
        return jsonify({"success": False, "error": "No data provided"})

    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    phone = data.get('phone', '').strip()
    dob = data.get('dob', '')
    gender = data.get('gender', '')
    
    if not email or not password:
        return jsonify({"success": False, "error": "Email and password required"})

    if len(password) < 4:
        return jsonify({"success": False, "error": "Password must be at least 4 characters"})
    
    result = create_user(name, email, password, phone, dob, gender)
    return jsonify(result)

@app.route('/api/login', methods=['POST'])
def api_login():
    """User login with database verification"""
    data = request.json
    if not data:
        return jsonify({"success": False, "error": "No data provided"})

    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    result = login_user(email, password)
    
    if result['success']:
        session['user_id'] = result['user']['id']
        session['user_name'] = result['user']['name']
        session['user_email'] = result['user']['email']
    
    return jsonify(result)

@app.route('/api/logout', methods=['POST'])
def api_logout():
    """User logout"""
    session.clear()
    return jsonify({"success": True, "message": "Logged out"})

@app.route('/api/reset-password', methods=['POST'])
def api_reset_password():
    """Reset user password"""
    data = request.json
    if not data:
        return jsonify({"success": False, "error": "No data provided"})

    email = data.get('email', '').strip().lower()
    new_password = data.get('newPassword', '')
    
    if not email or not new_password:
        return jsonify({"success": False, "error": "Email and new password required"})
    
    if len(new_password) < 4:
        return jsonify({"success": False, "error": "Password must be at least 4 characters"})
    
    result = reset_password(email, new_password)
    return jsonify(result)

@app.route('/api/user', methods=['GET'])
@login_required
def api_user():
    """Get current user info"""
    return jsonify({
        "success": True,
        "user": {
            "id": session.get('user_id'),
            "name": session.get('user_name'),
            "email": session.get('user_email')
        }
    })

@app.route('/api/language', methods=['GET', 'POST'])
@login_required
def api_language():
    """Get or set preferred language for the current session"""
    if request.method == 'POST':
        data = request.json or {}
        lang = data.get('lang', 'en')
        if lang not in ['en', 'hi', 'mr']:
            return jsonify({"success": False, "error": "Unsupported language. Use: en, hi, mr"})
        session['lang'] = lang
        return jsonify({"success": True, "lang": lang})
    else:
        return jsonify({"success": True, "lang": session.get('lang', 'en')})

@app.route('/api/analyze', methods=['POST'])
@login_required
def api_analyze():
    """Analyze plant image using Gemini Vision API with database storage"""
    try:
        if 'image' not in request.files:
            return jsonify({"success": False, "error": "No image provided"})
            
        image_file = request.files['image']

        # Security: validate file extension
        if not allowed_file(image_file.filename):
            return jsonify({"success": False, "error": "Invalid file type. Please upload an image (jpg, png, gif, webp)."})

        image_bytes = image_file.read()

        # Security: limit file size server-side (10MB)
        if len(image_bytes) > 10 * 1024 * 1024:
            return jsonify({"success": False, "error": "Image too large. Maximum size is 10MB."})
        
        # Save image locally with safe filename
        safe_filename = f"scan_{len(os.listdir(UPLOAD_FOLDER))}_{session.get('user_id')}.jpg"
        image_path = os.path.join(UPLOAD_FOLDER, safe_filename)
        with open(image_path, 'wb') as f:
            f.write(image_bytes)

        # Gemini Vision Integration
        import google.generativeai as genai
        from dotenv import load_dotenv
        import PIL.Image
        import io
        import json
        
        load_dotenv()
        api_key = os.getenv('GEMINI_API_KEY')
        
        if not api_key:
             return jsonify({"success": False, "error": "Gemini API Key not found"})

        genai.configure(api_key=api_key)
        
        # Prepare image for Gemini (optimized for low memory)
        img = PIL.Image.open(io.BytesIO(image_bytes))
        img = img.convert('RGB')
        img.thumbnail((512, 512))
        
        buffer = io.BytesIO()
        img.save(buffer, format='JPEG', quality=85)
        buffer.seek(0)
        img = PIL.Image.open(buffer)

        # Language-aware prompt
        lang = session.get('lang', 'en')
        lang_instruction = {
            'en': 'Respond with all text fields (disease name, precautions, treatments) in English.',
            'hi': 'सभी टेक्स्ट फ़ील्ड (रोग का नाम, सावधानियां, उपचार) हिंदी में दें।',
            'mr': 'सर्व मजकूर फील्ड (रोगाचे नाव, खबरदारी, उपचार) मराठीत द्या.'
        }

        prompt = f"""
        Analyze this image of a plant leaf. {lang_instruction.get(lang, lang_instruction['en'])}
        Return a JSON object with the following fields:
        1. plantName: The name of the plant (e.g., "Tomato", "Potato", "Pepper").
        2. disease: The name of the disease or "Healthy" if no disease is found.
        3. confidence: A percentage string (e.g., "95%") indicating confidence in the diagnosis.
        4. health_score: A number from 0 to 100 representing the plant's health (100 is perfectly healthy).
        5. isUnknown: Boolean, set to true ONLY if the image is clearly NOT a plant.
        6. precautions: An array of 4-5 precaution strings that should be followed.
        7. organic_manures: An array of 3-4 organic treatment recommendations with details.
        8. inorganic_manures: An array of 2-3 chemical/inorganic treatment recommendations.
        
        If the plant is healthy, provide general care tips in precautions and preventive treatments in organic/inorganic sections.
        
        Output ONLY the raw JSON string, no markdown formatting.
        """
        
        models_to_try = [
            'gemini-2.5-flash-lite',
            'gemini-2.5-flash-lite-preview-09-2025',
            'gemini-pro-latest',
            'gemini-1.5-flash',
            'gemini-1.5-flash-latest',
            'gemini-2.0-flash-exp'
        ]
        
        gemini_response = None
        last_error = None
        used_model = None

        print("--- Starting Model Attempt Loop ---")
        for model_name in models_to_try:
            try:
                print(f"Trying model: {model_name}")
                model = genai.GenerativeModel(model_name)
                gemini_response = model.generate_content([prompt, img])
                used_model = model_name
                print(f"Success with model: {model_name}")
                break
            except Exception as e:
                print(f"Failed with {model_name}: {e}")
                last_error = e
                continue
        
        if not gemini_response:
            try:
                print("All models failed. Available models:")
                for m in genai.list_models():
                    if 'generateContent' in m.supported_generation_methods:
                        print(f" - {m.name}")
            except:
                pass
            raise last_error or Exception("All models failed")

        print("Debugging Gemini Response:")
        try:
            print(f"Safety Ratings: {gemini_response.prompt_feedback}")
        except:
            pass
            
        try:
            text_response = gemini_response.text.strip()
            print(f"Raw Text Response: {text_response}")
        except Exception as e:
             print(f"Error accessing .text: {e}")
             if gemini_response.candidates and gemini_response.candidates[0].finish_reason:
                 return jsonify({"success": False, "error": f"Image blocked due to safety filters ({gemini_response.candidates[0].finish_reason})"})
             return jsonify({"success": False, "error": "No text returned from AI"})

        # Clean up any markdown formatting if present
        if text_response.startswith('```json'):
            text_response = text_response[7:]
        if text_response.startswith('```'):
            text_response = text_response[3:]
        if text_response.endswith('```'):
            text_response = text_response[:-3]
            
        try:
            result = json.loads(text_response.strip())
            result['success'] = True
            result['used_model'] = used_model 
        except json.JSONDecodeError as je:
            print(f"JSON Decode Error: {je}")
            return jsonify({"success": False, "error": f"Failed to parse AI response: {str(je)}"})

        # Prepare consolidated treatment string for database
        precautions = result.get('precautions', [])
        organic = result.get('organic_manures', [])
        inorganic = result.get('inorganic_manures', [])
        
        treatment_summary = "Precautions:\n" + "\n".join(f"- {p}" for p in precautions)
        treatment_summary += "\n\nOrganic Manures:\n" + "\n".join(f"- {o}" for o in organic)
        treatment_summary += "\n\nInorganic Manures:\n" + "\n".join(f"- {i}" for i in inorganic)

        # Save to database
        user_id = session.get('user_id')
        save_diagnosis(
            user_id=user_id,
            plant_name=result.get('plantName', 'Unknown'),
            disease=result.get('disease', 'Unknown'),
            confidence=result.get('confidence', '0%'),
            treatment=treatment_summary,
            image_path=image_path,
            health_score=result.get('health_score'),
            is_unknown=result.get('isUnknown', False)
        )
        
        return jsonify(result)

    except Exception as e:
        print(f"Analysis Error Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/history', methods=['GET'])
@login_required
def api_history():
    """Get diagnosis history from database"""
    user_id = session.get('user_id')
    history = get_diagnosis_history(user_id, limit=20)
    return jsonify({"success": True, "history": history})

@app.route('/api/stats', methods=['GET'])
@login_required
def api_stats():
    """Get diagnosis statistics"""
    user_id = session.get('user_id')
    stats = get_diagnosis_stats(user_id)
    return jsonify({"success": True, "stats": stats})

@app.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    """Chat endpoint with Gemini AI and database storage"""
    data = request.json
    if not data:
        return jsonify({"success": False, "error": "No data provided"})

    message = data.get('message', '').strip()
    if not message:
        return jsonify({"success": False, "error": "Empty message"})

    # Language-aware chat
    lang = session.get('lang', data.get('lang', 'en'))
    lang_instruction = {
        'en': 'Respond in English.',
        'hi': 'हिंदी में जवाब दें।',
        'mr': 'मराठीत उत्तर द्या.'
    }

    # Gemini Chat Integration
    try:
        import google.generativeai as genai
        import os
        from dotenv import load_dotenv
        
        load_dotenv()
        api_key = os.getenv('GEMINI_API_KEY')
        
        if api_key:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            prompt = f"""You are a helpful and knowledgeable Plant Expert AI. 
            {lang_instruction.get(lang, lang_instruction['en'])}
            User's question: {message}
            
            Provide a helpful, accurate, and friendly response. 
            You can give detailed advice but keep it easy to understand.
            If the question is not about plants, gardening, or agriculture, politely steer the conversation back to plants.
            """
            
            gemini_response = model.generate_content(prompt)
            response = gemini_response.text
        else:
            response = "Error: Gemini API key not configured."
            
    except Exception as e:
        print(f"Gemini Error: {str(e)}")
        response = "I'm having trouble connecting right now. Please try again in a moment."

    # Save to database
    user_id = session.get('user_id')
    save_chat(user_id, message, response)
    
    return jsonify({"success": True, "response": response})

if __name__ == '__main__':
    print("🌿 PlantCare AI Server Starting...")
    print("🔐 Authentication: Enabled")
    print("🌐 Language: English / Hindi / Marathi")
    print("📱 Open http://localhost:5000 in your browser")
    print("📱 For mobile: http://<your-ip>:5000")
    print("💾 Database: SQLite (plantcare.db)")
    app.run(debug=True, host='0.0.0.0', port=5000)
