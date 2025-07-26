import random
from flask import Blueprint, app, flash, redirect, render_template, request, session, url_for
from flask_mail import Message
from app.models.user import User

from app import db, mail
from app.models.user import User
from app.utils.token import generate_verification_token,confirm_verification_token
from app.utils.otp_utils import generate_and_store_otp,validate_otp

auth_bp = Blueprint('auth', __name__)
# otp_store = {}

@auth_bp.route('/')
def home():
    return render_template('base.html')

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('auth.signup'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('User already exists with this email!', 'warning')
            return redirect(url_for('auth.signup'))
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        token=generate_verification_token(email=email)
        # verify_url=url_for('auth.verify_email',token=token,__external=True)
        verify_url = request.host_url.rstrip('/') + url_for('auth.verify_email', token=token)
        
        msg = Message(
        subject="Email Verification",
        recipients=[email],
        sender="noreply@example.com"
        )

        msg.html = f"""
        <html>
          <body>
            <p>Hi {username},</p>
            <p>Please verify your email by clicking the link below:</p>
            <p><a href="{verify_url}">Verify Email</a></p>
          </body>
        </html>
        """

        mail.send(msg)
        verify_url = url_for('auth.verify_email', token=token, __external=True)
        
     
        # flash('Signup successful. Please log in!', 'success')
        # return redirect(url_for('auth.login'))

    return render_template('signup.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password) and user.is_verified:
            session['user_id'] = user.id
            session['username'] = user.username
            session['email'] = user.email
            flash('Login successful!', 'success')
            return redirect(url_for('auth.dashboard'))
        else:
            flash('Invalid email or password!', 'danger')
            return redirect(url_for('auth.login'))

    return render_template('login.html')


@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('No user found with this email.', 'danger')
            return redirect(url_for('auth.forgot_password'))

        # otp = str(random.randint(100000, 999999))
        # otp_store[email] = otp
        otp=generate_and_store_otp(user)

        msg = Message('Password Reset OTP', sender='noreply@example.com', recipients=[email])
        msg.body = f'Your OTP for password reset is: {otp}'
        mail.send(msg)

        flash('OTP sent to your email. Check your inbox.', 'info')
        return render_template('verify_otp.html', email=email)

    return render_template('forgot_password.html')


@auth_bp.route('/verify_otp', methods=['POST'])
def verify_otp():
    email = request.form.get('email')
    entered_otp = request.form.get('otp')
    
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    from app.utils.otp_utils import validate_otp
    if validate_otp(user, entered_otp):
        flash('OTP verified. Please enter a new password.', 'success')
        return render_template('reset_password.html', email=email)
    else:
        flash('Invalid or expired OTP.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    # if otp_store.get(email) == entered_otp:
    #     flash('OTP verified. Please enter new password.', 'success')
    #     return render_template('reset_password.html', email=email)
    # else:
    #     flash('Invalid OTP. Try again.', 'danger')
    #     return redirect(url_for('auth.forgot_password'))


@auth_bp.route('/reset_password', methods=['POST'])
def reset_password():
    email = request.form['email']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    

    if new_password != confirm_password:
        flash('Passwords do not match!', 'danger')
        return render_template('reset_password.html', email=email)

    user = User.query.filter_by(email=email).first()
    if user:
        print(f"[DEBUG] Old Hash: {user.password_hash}")
        user.set_password(new_password)
        print(f"[DEBUG] New Hash: {user.password_hash}")
        db.session.commit()
        # otp_store.pop(email, None)
        flash('Password reset successful. Please login.', 'success')
        return redirect(url_for('auth.login'))
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.forgot_password'))
    
@auth_bp.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('auth.login'))

    return render_template('dashboard.html', username=session.get('username'))

@auth_bp.route('/verify/<token>')
def verify_email(token):
    from app.utils.token import confirm_verification_token

    email = confirm_verification_token(token)
    if not email:
        flash('The verification link is invalid or has expired.')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.')
        return redirect(url_for('auth.signup'))

    if user.is_verified:
        flash('Account already verified. Please login.')
    else:
        user.is_verified = True
        db.session.commit()
        flash('You have successfully verified your account.')

    return redirect(url_for('auth.login'))
