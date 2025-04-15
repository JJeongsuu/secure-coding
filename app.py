import sqlite3
import uuid
#Hash 암호화
import bcrypt
import os
import html
import time
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send, emit
#Flask-WTF 기반 Register Form 모듈
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Regexp
from datetime import timedelta   #세션 시간위해서
from datetime import datetime
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

last_message_time = {}
MESSAGE_COOLDOWN = 1.5

# 신고관련 로그 파일 저장 설정
logging.basicConfig(
    filename='report_audit.log',
    level=logging.INFO,
    format='[%(asctime)s] %(message)s'
)

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

#상품 등록 세부정보 삭제 클래스
class DeleteForm(FlaskForm):
    submit = SubmitField('삭제')

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
    if 'user_id' not in session:
        flash("로그인 필요")
        return redirect(url_for('login'))
    
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
    return render_template('view_product.html', product=product, seller=seller, form=DeleteForm())

#상세정보 수정
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    # 접근 권한 체크
    if not product or product['seller_id'] != session['user_id']:
        flash('수정 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    form = ProductForm(data=product)
    if form.validate_on_submit():
        title = form.title.data
        description = form.description.data
        price = form.price.data
        cursor.execute(
            "UPDATE product SET title=?, description=?, price=? WHERE id=?",
            (title, description, price, product_id)
        )
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    return render_template('edit_product.html', form=form, product=product)


# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    form = ReportForm()

    if form.validate_on_submit():
        target_id = html.escape(form.target_id.data.strip())
        reason = html.escape(form.reason.data.strip())
        db = get_db()
        cursor = db.cursor()

        # 하루 신고 횟수 제한
        cursor.execute(
            "SELECT COUNT(*) FROM report WHERE reporter_id = ? AND timestamp > datetime('now', '-1 day')",
            (session['user_id'],)
        )
        count = cursor.fetchone()[0]
        if count >= 5:
            flash('하루 신고 가능 횟수를 초과했습니다.')
            return redirect(url_for('dashboard'))

        # 중복 신고 제한 (24시간 이내 동일 대상)
        cursor.execute(
            "SELECT * FROM report WHERE reporter_id = ? AND target_id = ? AND timestamp > datetime('now', '-1 day')",
            (session['user_id'], target_id)
        )
        existing_report = cursor.fetchone()
        if existing_report:
            flash('이미 해당 대상을 최근에 신고한 기록이 있습니다.')
            return redirect(url_for('dashboard'))

        # 신고 저장
        report_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        status = "미처리"
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason, timestamp, status) VALUES (?, ?, ?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason, timestamp, status)
        )
        db.commit()

        # 감사 로그 남기기
        l# 민감한 신고 사유 마스킹
        masked_reason = reason[:20].replace("\n", " ").replace("\r", " ")
        if len(reason) > 20:
            masked_reason += "..."

        logging.info(f"[신고] 사용자 {session['user_id']}가 대상 {target_id}를 신고함. 일부 사유: '{masked_reason}' (신고ID: {report_id})")



        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html', form=form)




#관리자 라우트 신고목록 확인 / 상태 변경
@app.route('/admin/reports')
def admin_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 관리자 권한 확인
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    admin = cursor.fetchone()
    if not admin or admin['is_admin'] != 1:
        flash("접근 권한이 없습니다.")
        return redirect(url_for('dashboard'))

    # 신고 목록 조회
    cursor.execute("SELECT * FROM report ORDER BY timestamp DESC")
    reports = cursor.fetchall()
    return render_template('admin_reports.html', reports=reports)



#관리자 상태 처리 라우트  
@app.route('/admin/report/<report_id>/process', methods=['POST'])
def process_report(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    admin = cursor.fetchone()
    if not admin or admin['is_admin'] != 1:
        flash("권한 없음")
        return redirect(url_for('dashboard'))

    new_status = request.form.get('status')
    if new_status not in ['처리됨', '무시됨']:  # 허용된 상태만
        flash("잘못된 상태입니다.")
        return redirect(url_for('admin_reports'))

    cursor.execute("UPDATE report SET status = ? WHERE id = ?", (new_status, report_id))
    db.commit()
    flash("신고 상태 변경 완료")
    return redirect(url_for('admin_reports'))




# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    if 'user_id' not in session:
        emit('error', {'error': '로그인이 필요합니다.'}, room=request.sid)
        return

    user_id = session['user_id']
    now = time.time()

    # 메시지 속도 제한 (스팸 방지)
    last_time = last_message_time.get(user_id, 0)
    if now - last_time < MESSAGE_COOLDOWN:
        emit('error', {'error': '메시지를 너무 자주 보낼 수 없습니다.'}, room=request.sid)
        return
    last_message_time[user_id] = now  # 현재 시간 저장

    # 구조 검증
    if not isinstance(data, dict) or 'message' not in data:
        emit('error', {'error': '잘못된 데이터 형식입니다.'}, room=request.sid)
        return

    message = data.get('message', '').strip()

    # 타입 체크
    if not isinstance(message, str):
        emit('error', {'error': '메시지는 문자열이어야 합니다.'}, room=request.sid)
        return

    # 길이 제한
    if not message or len(message) > 200:
        emit('error', {'error': '메시지는 1~200자여야 합니다.'}, room=request.sid)
        return

    # XSS 방지 이스케이프 처리
    safe_message = html.escape(message)

    # 안전하게 재구성된 데이터 전송
    data['message'] = safe_message
    data['message_id'] = str(uuid.uuid4())
    data['user_id'] = user_id

    send(data, broadcast=True)




#관리자 페이지
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
@app.route('/admin/block_target/<report_id>')
def block_target(report_id):
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

#작성자가 상세정보에서 내역 삭제할 수 있도록 
@app.route('/product/delete/<product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 존재 여부 확인
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash("상품이 존재하지 않습니다.")
        return redirect(url_for('dashboard'))

    # 작성자 본인 확인
    if product['seller_id'] != session['user_id']:
        flash("삭제 권한이 없습니다.")
        return redirect(url_for('dashboard'))

    # 삭제 수행
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash("상품이 삭제되었습니다.")
    return redirect(url_for('dashboard'))


#사용자에게 에러 보여주기
@app.errorhandler(500)
def internal_server_error(error):
    return render_template("500.html"), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404


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

#과제 제출 시 db초기화를 막기 위해  관리자 계정을 자동 생성하기기
def ensure_admin():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE username = 'admin'")
    if not cursor.fetchone():
        admin_id = str(uuid.uuid4())
        hashed_pw = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO user (id, username, password, is_admin, balance) VALUES (?, ?, ?, ?, ?)",
            (admin_id, "admin", hashed_pw, 1, 10000)
        )
        db.commit()
        print("기본 관리자 계정(admin / admin123) 자동 생성됨")

def ensure_user_columns():
    db = get_db()
    cursor = db.cursor()
    # user 테이블 컬럼 목록 가져오기
    cursor.execute("PRAGMA table_info(user)")
    columns = [row[1] for row in cursor.fetchall()]  # row[1]은 컬럼 이름

    if 'is_admin' not in columns:
        cursor.execute("ALTER TABLE user ADD COLUMN is_admin INTEGER DEFAULT 0")
        print("is_admin 컬럼 자동 추가됨")

    if 'balance' not in columns:
        cursor.execute("ALTER TABLE user ADD COLUMN balance INTEGER DEFAULT 10000")
        print("balance 컬럼 자동 추가됨")

    db.commit()


#Content-Security-Policy, X-Frame-Options, X-Content-Type-Options 보안 헤더 적용
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    with app.app_context():
        ensure_user_columns()
        ensure_admin() 
    socketio.run(app, debug=True)





