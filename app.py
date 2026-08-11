from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

# Initialize Flask Application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'mist-salsa-ku-vibrant-key-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mist_salsa.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Token Serializer for Account Recovery Links
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# ==========================================
# DATABASE MODELS
# ==========================================

class Member(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='Client')  # 'Client', 'Committee', 'Executive'
    position = db.Column(db.String(50), default='Member')              # e.g., 'President', 'Instructor', 'Treasurer'
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Fine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    reason = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='Unpaid')                 # 'Unpaid' or 'Paid'
    date_issued = db.Column(db.DateTime, default=datetime.utcnow)
    
    member = db.relationship('Member', backref=db.backref('fines', lazy=True))


class DutyRoster(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=False)
    duty_name = db.Column(db.String(100), nullable=False)
    duty_date = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Scheduled')              # 'Scheduled', 'Completed'
    
    member = db.relationship('Member', backref=db.backref('rosters', lazy=True))


class DanceClass(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    dance_style = db.Column(db.String(50), nullable=False)              # 'Salsa', 'Bachata', 'Kompa'
    category = db.Column(db.String(20), nullable=False)                 # 'Client' or 'Committee'
    schedule = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return Member.query.get(int(user_id))


# ==========================================
# PUBLIC & AUTHENTICATION ROUTES
# ==========================================

@app.route('/')
def index():
    """ Public Homepage """
    client_classes = DanceClass.query.filter_by(category='Client').all()
    return render_template('index.html', classes=client_classes)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Committee Admin Login """
    if current_user.is_authenticated:
        return redirect(url_for('portal'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        member = Member.query.filter_by(email=email).first()

        if member and member.check_password(password):
            if member.role in ['Committee', 'Executive']:
                login_user(member)
                flash('Successfully logged in to Admin Portal.', 'success')
                return redirect(url_for('portal'))
            else:
                flash('Access denied. Admin portal is reserved for committee members.', 'danger')
        else:
            flash('Invalid email or password. Please try again.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """ Logout Admin """
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ==========================================
# ACCOUNT RECOVERY / FORGOT PASSWORD
# ==========================================

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """ Request Password Recovery Link """
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        member = Member.query.filter_by(email=email).first()

        if member:
            # Generate timed token valid for 15 minutes (900 seconds)
            token = serializer.dumps(member.email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)

            # Prints reset link to console for local testing
            print("\n" + "="*60)
            print(f" PASSWORD RESET REQUESTED FOR: {member.email}")
            print(f" RESET LINK: {reset_url}")
            print("="*60 + "\n")

            flash('A password reset link has been generated. (Check server console for local testing)', 'info')
        else:
            # Generic message to prevent user enumeration
            flash('If an account exists with that email, a password reset link has been sent.', 'info')

        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """ Reset Password with Token """
    try:
        # Validate token expiration (15 mins)
        email = serializer.loads(token, salt='password-reset-salt', max_age=900)
    except SignatureExpired:
        flash('The password reset link has expired. Please request a new one.', 'danger')
        return redirect(url_for('forgot_password'))
    except BadTimeSignature:
        flash('Invalid password reset token.', 'danger')
        return redirect(url_for('login'))

    member = Member.query.filter_by(email=email).first_or_404()

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
        else:
            member.set_password(new_password)
            db.session.commit()
            flash('Your password has been successfully reset! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


# ==========================================
# PROTECTED COMMITTEE ADMIN DASHBOARD
# ==========================================

@app.route('/portal')
@login_required
def portal():
    """ Committee & Leadership Admin Dashboard """
    if current_user.role not in ['Committee', 'Executive']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('index'))

    members = Member.query.all()
    fines = Fine.query.all()
    rosters = DutyRoster.query.all()
    committee_classes = DanceClass.query.filter_by(category='Committee').all()

    return render_template(
        'portal.html', 
        members=members, 
        fines=fines, 
        rosters=rosters, 
        classes=committee_classes
    )


@app.route('/induct_member', methods=['POST'])
@login_required
def induct_member():
    """ Induct new member with initial default password """
    name = request.form.get('name')
    email = request.form.get('email')
    role = request.form.get('role', 'Client')
    position = request.form.get('position', 'Member')
    initial_password = request.form.get('password', 'Salsa2026!')

    if name and email:
        if Member.query.filter_by(email=email).first():
            flash('Member with this email already exists.', 'warning')
        else:
            new_member = Member(name=name, email=email, role=role, position=position)
            new_member.set_password(initial_password)
            db.session.add(new_member)
            db.session.commit()
            flash(f'Member {name} inducted successfully! Default Password: {initial_password}', 'success')
    
    return redirect(url_for('portal'))


@app.route('/update_position', methods=['POST'])
@login_required
def update_position():
    """ Update member role/position """
    member_id = request.form.get('member_id')
    new_role = request.form.get('role')
    new_position = request.form.get('position')

    member = Member.query.get(member_id)
    if member:
        if new_role:
            member.role = new_role
        if new_position:
            member.position = new_position
        db.session.commit()
        flash('Member updated successfully.', 'success')

    return redirect(url_for('portal'))


@app.route('/issue_fine', methods=['POST'])
@login_required
def issue_fine():
    """ Issue fine to a member """
    member_id = request.form.get('member_id')
    amount = request.form.get('amount')
    reason = request.form.get('reason')

    if member_id and amount and reason:
        new_fine = Fine(member_id=int(member_id), amount=float(amount), reason=reason)
        db.session.add(new_fine)
        db.session.commit()
        flash('Fine issued successfully.', 'success')

    return redirect(url_for('portal'))


@app.route('/pay_fine/<int:fine_id>', methods=['POST'])
@login_required
def pay_fine(fine_id):
    """ Mark fine as paid """
    fine = Fine.query.get(fine_id)
    if fine:
        fine.status = 'Paid'
        db.session.commit()
        flash('Fine marked as paid.', 'success')
    return redirect(url_for('portal'))


@app.route('/add_duty', methods=['POST'])
@login_required
def add_duty():
    """ Assign duty roster entry """
    member_id = request.form.get('member_id')
    duty_name = request.form.get('duty_name')
    duty_date = request.form.get('duty_date')

    if member_id and duty_name and duty_date:
        roster = DutyRoster(member_id=int(member_id), duty_name=duty_name, duty_date=duty_date)
        db.session.add(roster)
        db.session.commit()
        flash('Duty roster assigned.', 'success')

    return redirect(url_for('portal'))


@app.route('/add_class', methods=['POST'])
@login_required
def add_class():
    """ Add dance class schedule """
    title = request.form.get('title')
    dance_style = request.form.get('dance_style')
    category = request.form.get('category')
    schedule = request.form.get('schedule')
    location = request.form.get('location')

    if title and category:
        new_class = DanceClass(
            title=title, dance_style=dance_style, category=category,
            schedule=schedule, location=location
        )
        db.session.add(new_class)
        db.session.commit()
        flash('Dance class created.', 'success')

    return redirect(url_for('portal'))


# ==========================================
# INITIALIZATION & SEEDING
# ==========================================

def seed_default_data():
    """ Seed default admin user and initial classes """
    if Member.query.count() == 0:
        default_admin = Member(
            name="Admin President",
            email="admin@mistsalsa.co.ke",
            role="Executive",
            position="President"
        )
        default_admin.set_password("AdminSalsa2026!")
        db.session.add(default_admin)

    if DanceClass.query.count() == 0:
        default_classes = [
            DanceClass(
                title="Beginner Salsa & Bachata", dance_style="Salsa",
                category="Client", schedule="Tuesday 5:00 PM - 7:00 PM",
                location="Student Centre Grounds"
            ),
            DanceClass(
                title="Kompa Rhythms & Hip Movement", dance_style="Kompa",
                category="Client", schedule="Thursday 5:00 PM - 7:00 PM",
                location="Student Centre Grounds"
            ),
            DanceClass(
                title="Advanced Turn Patterns & Musicality", dance_style="Salsa",
                category="Committee", schedule="Saturday 2:00 PM - 5:00 PM",
                location="Main Gym Hall"
            )
        ]
        db.session.bulk_save_objects(default_classes)

    db.session.commit()



    with app.app_context():
        db.create_all()
        seed_default_data()
        
if __name__ == '__main__':    
    print("\n" + "="*50)
    print("  MIST Salsa KU Backend Server Running!")
    print("  Default Admin Login:")
    print("  Email   : admin@mistsalsa.co.ke")
    print("  Password: AdminSalsa2026!")
    print("  Portal  : http://127.0.0.1:5000/login")
    print("="*50 + "\n")
    
    app.run(debug=True, port=5000)