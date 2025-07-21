from flask import Flask, request, jsonify
from flask_cors import CORS
import pymysql

app = Flask(__name__)
CORS(app)

# MariaDB 연결 정보
db = pymysql.connect(
    host='172.18.1.200',
    user='hoteluser',
    password='pw1234',
    database='hotel_db',
)

# 회원가입
@app.route('/register', methods=['POST'])
def register():
    data = request.form
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not all([name, email, phone, username, password, confirm_password]):
        return jsonify({'result': 'fail', 'msg': '모든 필드를 입력해주세요.'}), 400

    if password != confirm_password:
        return jsonify({'result': 'fail', 'msg': '비밀번호가 일치하지 않습니다.'}), 400

    try:
        with db.cursor() as cursor:
            sql = "INSERT INTO users (name, email, phone, username, password) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(sql, (name, email, phone, username, password))

            db.commit()
        return jsonify({'result': 'success', 'msg': '회원가입 성공!'})
    except Exception as e:
        db.rollback()
        return jsonify({'result': 'fail', 'msg': str(e)}), 500

# 로그인 (username + password)
@app.route('/login', methods=['POST'])
def login():
    data = request.form
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'result': 'fail', 'msg': '아이디와 비밀번호를 모두 입력해주세요.'}), 400

    try:
        with db.cursor() as cursor:
            sql = "SELECT * FROM users WHERE username=%s AND password=%s"
            cursor.execute(sql, (username, password))
            user = cursor.fetchone()
            if user:
                return jsonify({'result': 'success', 'msg': '로그인 성공!', 'username': username})
            else:
                return jsonify({'result': 'fail', 'msg': '아이디 또는 비밀번호가 올바르지 않습니다.'}), 401
    except Exception as e:
        return jsonify({'result': 'fail', 'msg': str(e)}), 500

# 예약 저장 (username 기반)
@app.route('/reservations', methods=['POST'])
def reserve():
    data = request.form
    username = data.get('username')
    reserver_name = data.get('reserver_name')
    phone = data.get('phone')
    hotel = data.get('hotel')
    checkin = data.get('checkin')
    checkout = data.get('checkout')
    payment_method = data.get('payment')

    total_price = data.get('totalPrice', '0').replace(',', '')

    if not all([username, reserver_name, phone, hotel, checkin, checkout, payment_method, total_price]):
        return jsonify({'result': 'fail', 'msg': '모든 필드를 입력해주세요.'}), 400

    try:
        with db.cursor() as cursor:
            sql = """
                INSERT INTO reservations
                (username, reserver_name, phone, hotel, checkin, checkout, payment_method, total_price)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (username, reserver_name, phone, hotel, checkin, checkout, payment_method, total_price))
            db.commit()
        return jsonify({'result': 'success', 'msg': '예약이 완료되었습니다!'})
    except Exception as e:
        db.rollback()
        return jsonify({'result': 'fail', 'msg': str(e)}), 500

# 마이페이지 - 내 예약 내역 조회 (username 기반)
@app.route('/reservations')
def reservations():
    username = request.args.get('username')
    if not username:
        return jsonify({'result': 'fail', 'msg': '로그인 정보가 없습니다.'}), 400
    try:
        with db.cursor(pymysql.cursors.DictCursor) as cursor:
            sql = """
                SELECT reserver_name, phone, hotel, checkin, checkout, payment_method, total_price
                FROM reservations
                WHERE username=%s
                ORDER BY checkin DESC
            """
            cursor.execute(sql, (username,))
            rows = cursor.fetchall()
        return jsonify({'result': 'success', 'data': rows})
    except Exception as e:
        return jsonify({'result': 'fail', 'msg': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
