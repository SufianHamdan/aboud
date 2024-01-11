from datetime import timedelta
from flask import Flask, abort, jsonify, render_template, request, session, redirect, url_for
from flask_socketio import join_room, leave_room, send, SocketIO
import random

import requests
import os
from string import ascii_uppercase

# Encryptions libraries
import base64

# from cryptography.fernet import Fernet 


app = Flask(__name__)
app.secret_key = os.urandom(24)
SocketIO = SocketIO(app)


# Set session timeout to 30 minutes
app.permanent_session_lifetime = timedelta(minutes=30)



app.config.update(
    # his setting instructs Flask to set the Secure flag on the session cookie. When the Secure flag is set
    SESSION_COOKIE_SECURE=True,
    # mitigate Cross-Site Scripting (XSS) attacks.This setting instructs Flask to set the HttpOnly flag on the session cookie. The HttpOnly flag restricts access to the cookie to HTTP requests and prevents client-side scripts (such as JavaScript) from accessing the cookie
    SESSION_COOKIE_HTTPONLY=True,
    # flag on the "remember me" cookie. It ensures that the "remember me" cookie is only sent over secure, HTTPS connections
    REMEMBER_COOKIE_SECURE=True,
    # It restricts access to the cookie to HTTP requests and enhances security.
    REMEMBER_COOKIE_HTTPONLY=True
)
#to check if working remove comments
#print(app.config['SESSION_COOKIE_SECURE'])  
#print(app.config['SESSION_COOKIE_HTTPONLY'])  
#print(app.config['REMEMBER_COOKIE_SECURE'])
#print(app.config['REMEMBER_COOKIE_HTTPONLY'])  




@app.after_request
def add_secure_headers(response):
    # mitigate certain types of attacks, such as MIME-sniffing attacks.
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # prevents your web pages from being embedded into frames. It helps protect against clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # no referrer information is sent in the HTTP headers, providing more privacy
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response






# Cross-Site Request Forgery) protection to your Flask application. CSRF is an attack that tricks the victim into submitting a malicious request. To protect against CSRF, Flask provides a built-in mechanism known as the "session" to generate and validate CSRF tokens
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(403)

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = os.urandom(24).hex()
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token




@app.after_request
def add_secure_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response




# Set Content Security Policy (CSP)
# adds a Content Security Policy (CSP) header to the HTTP response, specifying the rules for loading scripts and styles on the web page. The goal is to enhance security by controlling the sources from which scripts and styles can be loaded, thereby mitigating certain types of security vulnerabilities, such as Cross-Site Scripting (XSS)
# @app.after_request
# def add_security_headers(response):
   # response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.socket.io; style-src 'self' 'unsafe-inline';"
   # return response

# Set Strict-Transport-Security (HSTS)
# adds the Strict-Transport-Security (HSTS) header to the HTTP response. HSTS instructs the browser to always use a secure (HTTPS) connection with the specified policy settings. This helps protect against certain types of attacks, such as SSL-stripping attacks
#@app.after_request
#def add_hsts_header(response):
    #response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    #return response




rooms = {}



#OpenWetherMap
OPENWEATHERMAP_API_KEY = '801ec2939660ae68eb13c47a0806d401'

def get_weather(city):
    url = f'http://api.openweathermap.org/data/2.5/weather?q={city}&appid={OPENWEATHERMAP_API_KEY}&units=metric'
    response = requests.get(url)
    data = response.json()

    if response.status_code == 200:
        # Extract relevant weather information (modify as needed)
        weather_info = {
            'description': data['weather'][0]['description'],
            'temperature': data['main']['temp'],
            'icon_code': data['weather'][0]['icon'],
        }
        
        weather_info["temperature"] = round(weather_info["temperature"])
        weather_info['icon_url'] = f'http://openweathermap.org/img/wn/{weather_info["icon_code"]}.png'
        return weather_info
    else:
        return None


    


# Encrypt message function
# Replace this key and IV with strong, random values


# key = 'YOE5yD1awQB6lxhIFwSmYo9LBJrTH8TlWCGcE0OJ2nI=' 
# cipher_suite = Fernet(key)

# def encrypt_Fernet(encrypted_message):
#     encrypted_message = cipher_suite.encrypt(bytes(encrypted_message, 'utf-8'))
#     encrypted_message_base64 = base64.b64encode(encrypted_message).decode('utf-8')
#     print(encrypted_message_base64) 
#     return encrypted_message_base64

# def decrypt_Fernet(encrypted_message_base64):
#     encrypted_message = base64.b64decode(encrypted_message_base64)
#     decrypted_message = cipher_suite.decrypt(encrypted_message).decode('utf-8')
#     print(decrypted_message)
#     return decrypted_message
    






def generate_unique_code(length):
    while True:
        code = ""
        for _ in range(length):
            code += random.choice(ascii_uppercase)
        
        if code not in rooms:
            break
    
    return code

@app.route("/", methods=["POST", "GET"])
def home():
    session.clear()
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get("create", False)

        if not name:
            return render_template("home.html", error="Please enter a name.", code=code, name=name)

        if join != False and not code:
            return render_template("home.html", error="Please enter a room code.", code=code, name=name)
        
        room = code
        if create != False:
            room = generate_unique_code(4)
            rooms[room] = {"members": 0, "messages": []}
        elif code not in rooms:
            return render_template("home.html", error="Room does not exist.", code=code, name=name)
        
        session["room"] = room
        session["name"] = name
        return redirect(url_for("room"))

    return render_template("home.html")

@app.route("/room")
def room():
    room = session.get("room")
    if room is None or session.get("name") is None or room not in rooms:
        return redirect(url_for("home"))

    # Get weather information for demonstration purposes
    city = 'Amman'  # Replace with the actual city name or use geolocation to get the user's city
    weather_info = get_weather(city)

    return render_template("room.html", code=room, messages=rooms[room]["messages"], weather_info=weather_info )






@SocketIO.on("message")
def message(data):
    room = session.get("room")
    if room not in rooms:
        return 
    
    content = {
        "name": session.get("name"),
        "message": data['data']
        
    }
    
    send(content, to=room)
    rooms[room]["messages"].append(content)
    print(f"{session.get('name')} said: {content['message']} ")

@SocketIO.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name")
    if not room or not name:
        return
    if room not in rooms:
        leave_room(room)
        return
    
    join_room(room)
    send({"name": name, "message": "has entered the room"}, to=room)
    rooms[room]["members"] += 1
    print(f"{name} joined room {room}")

@SocketIO.on("disconnect")
def disconnect():
    room = session.get("room")
    name = session.get("name")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]
    
    send({"name": name, "message": "has left the room"}, to=room)
    print(f"{name} has left the room {room}")


@app.route("/styledroom")
def room2():
    return render_template("styledroom.html" )


if __name__ == "__main__":
    SocketIO.run(app, host='0.0.0.0', port=5000, debug=True)