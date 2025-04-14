import sqlite3
import uuid
#Hash 암호화
import bcrypt
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
#Flask-WTF 기반 Register Form 모듈
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Regexp
from datetime import timedelta   #세션 시간위해서
from time import sleep


app = Flask(__name__)

csrf = CSRFProtect(app)   #csrf 활성화
DATABASE = 'market.db'
socketio = SocketIO(app)
app.config['SECRET_KEY'] = os.urandom(24) 

# 보안 세션 설정 추가
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS 환경에서만 동작
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

#세션 만료 시간 적용
@app.before_request
def make_session_permanent():
    session.permanent = True


# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# RegisterForm 클래스 정의
class RegisterForm(FlaskForm):
    username = StringField('사용자명', validators=[
        DataRequired(), 
        Length(min=3, max=20), 
        Regexp(r'^[a-zA-Z0-9_]+$', message="영문, 숫자, 언더스코어만 허용됩니다.")
    ])
    password = PasswordField('비밀번호', validators=[
        DataRequired(), 
        Length(min=6, max=100),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d).{8,}$', 
        message="비밀번호는 문자와 숫자를 포함해야 합니다.")
    ])
    submit = SubmitField('회원가입')

# LoginForm 클래스 정의
class LoginForm(FlaskForm):
    username = StringField('사용자명', validators=[
        DataRequired(),
        Length(min=4, max=100)
    ])
    password = PasswordField('비밀번호', validators=[
        DataRequired(),
        Length(min=6, max=100)
    ])
    submit = SubmitField('로그인')

#ProfileForm 클래스 정의
class ProfileForm(FlaskForm):
    bio = TextAreaField('소개글', validators=[Length(max=500)])
    submit = SubmitField('프로필 업데이트')

#상품등록 클래스 정의
class ProductForm(FlaskForm):
    title = StringField('제목', validators=[
        DataRequired(),
        Length(max=50)
    ])
    description = TextAreaField('설명', validators=[
        DataRequired(),
        Length(max=1000)])
    price = StringField('가격', validators=[
        DataRequired(),
        Regexp(r'^\d+(\.\d{1,2})?$', message="가격은 숫자 형식이어야 합니다.")
    ])
    submit = SubmitField('상품 등록')

#신고페이지 클래스 정의 
class ReportForm(FlaskForm):
    target_id = StringField('신고 대상 ID', validators=[
        DataRequired(),
        Length(min=4)
    ])
    reason = TextAreaField('신고 사유', validators=[
        DataRequired(),
        Length(min=5, max=500)
    ])
    submit = SubmitField('신고하기')

#송금 클래스
class TransferForm(FlaskForm):
    receiver_username = StringField('받는 사용자명', validators=[DataRequired()])
    amount = StringField('금액', validators=[
        DataRequired(),
        Regexp(r'^\d+$', message="숫자만 입력하세요.")
    ])
    password = PasswordField('비밀번호 확인', validators=[DataRequired()])
    submit = SubmitField('송금하기')


# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                    (user_id, username, hashed_pw))

        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        db = get_db()
        cursor = db.cursor()

        session['login_failures'] = session.get('login_failures', 0)

        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode(), user['password']):
            session.clear()  # session fixation 방지
            session['user_id'] = user['id']
            #관리자 --> /admin 으로 리디렉션
            if user['is_admin'] == 1:
                flash('관리자 로그인 성공!')
                return redirect(url_for('admin_panel'))
            
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        
        else:
            # 실패한 경우
            session['login_failures'] += 1
            if session['login_failures'] >= 5:
                sleep(3)  # 5회 이상 실패시 3초 딜레이
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html', form = form)

# 로그아웃
@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    form = ProfileForm()
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST' and form.validate_on_submit():
        bio = form.bio.data
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # bio 초기값 설정
    form.bio.data = current_user['bio']
    return render_template('profile.html', user=current_user, form = form)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    form = ProductForm()

    if form.validate_on_submit():
        title = form.title.data
        description = form.description.data
        price = form.price.data
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html', form = form)

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    form = ReportForm()

    if form.validate_on_submit():
        target_id = form.target_id.data
        reason = form.reason.data
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html', form = form)

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

#관리자 페이지지
@app.route('/admin')
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    if current_user['is_admin'] != 1:
        flash("접근 권한이 없습니다.")
        return redirect(url_for('dashboard'))

    # 유저, 상품, 신고 목록 가져오기
    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()
    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()
    cursor.execute("SELECT * FROM report")
    reports = cursor.fetchall()

    return render_template("admin.html", users=users, products=products, reports=reports)

#물건 검색 기능
@app.route('/search')
def search():
    keyword = request.args.get('q', '').strip()

    db = get_db()
    cursor = db.cursor()

    if keyword:
        cursor.execute("SELECT * FROM product WHERE title LIKE ?", (f'%{keyword}%',))
        results = cursor.fetchall()
    else:
        results = []

    return render_template('search.html', keyword=keyword, results=results)


#송금하기 
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = TransferForm()
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    sender = cursor.fetchone()

    if form.validate_on_submit():
        #비밀번호 재검증
        input_password = form.password.data
        if not bcrypt.checkpw(input_password.encode(), sender['password']):
            flash("비밀번호가 일치하지 않습니다.")
            return redirect(url_for('transfer'))
        
        receiver_name = form.receiver_username.data
        amount = int(form.amount.data)

        if sender['username'] == receiver_name:
            flash("자기 자신에게는 송금할 수 없습니다.")
            return redirect(url_for('transfer'))

        if sender['balance'] < amount:
            flash("잔액이 부족합니다.")
            return redirect(url_for('transfer'))

        # 수신자 찾기
        cursor.execute("SELECT * FROM user WHERE username = ?", (receiver_name,))
        receiver = cursor.fetchone()

        if not receiver:
            flash("받는 사용자가 존재하지 않습니다.")
            return redirect(url_for('transfer'))

        # 송금 실행
        cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, sender['id']))
        cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver['id']))
        db.commit()

        flash(f"{receiver_name}님에게 {amount}원 송금 완료!")
        return redirect(url_for('dashboard'))

    return render_template("transfer.html", form=form, balance=sender['balance'])

#관리자 페이지 --> 관리자가 사용자, 물건 신고 
@app.route('/admin/process_report/<report_id>')
def process_report(report_id):
    db = get_db()
    cursor = db.cursor()

    # 1. 신고 내용 가져오기
    cursor.execute("SELECT * FROM report WHERE id = ?", (report_id,))
    report = cursor.fetchone()
    if not report:
        flash("해당 신고가 존재하지 않습니다.")
        return redirect(url_for('admin_panel'))

    target_id = report['target_id']

    # 2. user 테이블에서 검색
    cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
    user = cursor.fetchone()

    if user:
        # 유저 차단
        cursor.execute("UPDATE user SET is_blocked = 1 WHERE id = ?", (target_id,))
        db.commit()
        flash(f"사용자 {user['username']} 차단 완료")
        return redirect(url_for('admin_panel'))

    # 3. product 테이블에서 검색
    cursor.execute("SELECT * FROM product WHERE id = ?", (target_id,))
    product = cursor.fetchone()

    if product:
        # 상품 차단
        cursor.execute("UPDATE product SET is_blocked = 1 WHERE id = ?", (target_id,))
        db.commit()
        flash(f"상품 '{product['title']}' 차단 완료")
        return redirect(url_for('admin_panel'))

    flash("신고 대상이 존재하지 않습니다.")
    return redirect(url_for('admin_panel'))


#관리자 페이지 --> 신고 삭제하기 (신고 취소하기)
@app.route('/admin/delete_report/<report_id>')
def delete_report(report_id):
    db = get_db()
    cursor = db.cursor()

    cursor.execute("DELETE FROM report WHERE id = ?", (report_id,))
    db.commit()

    flash("신고가 삭제되었습니다.")
    return redirect(url_for('admin_panel'))


#관리자 --> 사용자 상세 보기
@app.route('/admin/user/<user_id>')
def view_user(user_id):
    db = get_db()
    cursor = db.cursor()

    # 로그인한 사용자가 관리자여야 함
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    admin = cursor.fetchone()
    if not admin or admin['is_admin'] != 1:
        flash("접근 권한이 없습니다.")
        return redirect(url_for('dashboard'))

    # 조회할 유저 정보
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("해당 사용자가 존재하지 않습니다.")
        return redirect(url_for('admin_panel'))

    return render_template("user_detail.html", user=user)


##########보안 상 삭제하는 것이지만 과제제출이므로 주석처리로 삭제 표현
#DB에 반영
#@app.route('/add-admin-column')
#def add_admin_column():
#    db = get_db()
#    cursor = db.cursor()
#    try:
#        cursor.execute("ALTER TABLE user ADD COLUMN is_admin INTEGER DEFAULT 0")
#        db.commit()
#        return "is_admin 컬럼 추가"
#    except:
#        return "이미 존재/ 오류"


#관리자 페이지db
# @app.route('/create-admin')
# def create_admin():
#     db = get_db()
#     cursor = db.cursor()

#     import uuid

#     admin_id = str(uuid.uuid4())
#     hashed_pw = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
#     cursor.execute(
#         "INSERT INTO user (id, username, password, is_admin) VALUES (?, ?, ?, ?)",
#         (admin_id, "admin", hashed_pw, 1)
#     )
#     db.commit()
#     return "관리자 계정 생성"

#송금기능 db
# @app.route('/add-balance-column')
# def add_balance_column():
#     db = get_db()
#     cursor = db.cursor()
#     try:
#         cursor.execute("ALTER TABLE user ADD COLUMN balance INTEGER DEFAULT 10000")
#         db.commit()
#         return "balance 컬럼 추가 완료 초기값 10000원"
#     except:
#         return "이미 추가되어 있을 수 있음"


if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)





