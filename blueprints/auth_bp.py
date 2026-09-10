"""
OxWg Panel - Authentication Blueprint (auth_bp)
==============================================
Handles admin login, logout, registration, and initial 2FA enrollment.
Branding: "OxWg Panel" for 2FA issuer.
"""
import os
import json
import secrets
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    session,
    current_app,
)
from flask_login import (
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)

try:
    import pyotp
except ImportError:
    pyotp = None

from core.extensions import db
from core.crypto import (
    _gen_recovery,
    hash_recovery,
    verify_recovery,
)
from core.url_utils import _safe_url
from models import AdminAccount
from services.panel_settings import _is_https
from services.telegram_notifier import _send_security_notification
from services.http_security import (
    _http_security_record_login_failure,
    _request_client_ip,
)
from services.admin_log import _norm_adminlog

auth_bp = Blueprint('auth_bp', __name__)


class Admin(UserMixin):
    def __init__(self, username='admin'):
        self.id = '1'
        self.username = username
        self.is_admin = True
        self.is_superuser = True


def load_user(user_id):
    if user_id != '1':
        return None
    acc = AdminAccount.query.first()
    if not acc:
        return None
    return Admin(acc.username)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if not AdminAccount.query.first():
        return redirect(url_for('register'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = (request.form.get('password') or '').strip()
        otp = (
            request.form.get('twofa_code')
            or request.form.get('otp_or_recovery')
            or ''
        ).strip().replace(' ', '')

        account = AdminAccount.query.filter_by(username=username).first()

        if not account or not account.verify_pw(password):
            _send_security_notification(
                'login_failed',
                username=(username or 'unknown'),
                reason='Invalid username or password',
            )
            _http_security_record_login_failure(
                username=(username or 'unknown'),
                failure_type='credentials',
            )
            try:
                client_ip, _ = _request_client_ip()
                _norm_adminlog({
                    'action': 'login_failed',
                    'admin_username': (username or ''),
                    'details': f'ip={client_ip}; reason=invalid_credentials',
                    'result': 'denied',
                    'channel': 'web',
                })
            except Exception:
                pass

            flash('Invalid username or password', 'error')
            return render_template('login.html')

        if account.twofa_enabled:
            verified = False

            if account.totp_secret and otp and pyotp is not None:
                totp = pyotp.TOTP(account.totp_secret)
                if totp.verify(otp, valid_window=1):
                    verified = True

            if not verified and otp:
                recovery_codes = (account.recovery_codes or '').splitlines()
                for index, stored in enumerate(recovery_codes):
                    if verify_recovery(otp, stored):
                        verified = True
                        recovery_codes.pop(index)
                        account.recovery_codes = '\n'.join(recovery_codes)
                        db.session.commit()
                        break

            if not verified:
                _send_security_notification(
                    'twofa_failed',
                    username=account.username,
                    reason='Invalid TOTP or recovery code',
                )
                _http_security_record_login_failure(
                    username=account.username,
                    failure_type='twofa',
                )
                try:
                    client_ip, _ = _request_client_ip()
                    _norm_adminlog({
                        'action': 'twofa_failed',
                        'admin_username': account.username,
                        'details': f'ip={client_ip}; reason=invalid_twofa',
                        'result': 'denied',
                        'channel': 'web',
                    })
                except Exception:
                    pass

                flash('Enter your 6-digit code or a valid recovery code', 'error')
                return render_template('login.html')

        login_user(Admin(account.username))

        _send_security_notification(
            'login_success',
            username=account.username,
            reason=(
                'Password and two-factor checks passed'
                if account.twofa_enabled
                else 'Password accepted'
            ),
        )

        try:
            client_ip, _ = _request_client_ip()
            _norm_adminlog({
                'action': 'login_success',
                'admin_username': account.username,
                'details': f'ip={client_ip}; scheme={"https" if _is_https() else "http"}',
                'result': 'ok',
                'channel': 'web',
            })
        except Exception:
            pass

        next_url = request.form.get('next') or request.args.get('next')
        if next_url and _safe_url(next_url):
            return redirect(next_url)

        return redirect(url_for('index'))

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@auth_bp.route('/register/twofa_begin', methods=['POST'])
def register_twofa_begin():
    if AdminAccount.query.first():
        return jsonify({"error": "Registration closed"}), 403

    payload = request.get_json(silent=True) or {}
    account = (payload.get("username") or "admin").strip() or "admin"
    issuer = "OxWg Panel"

    if pyotp is None:
        return jsonify({"error": "pyotp library not available"}), 500

    secret = session.get("reg_totp_secret") or pyotp.random_base32()
    session["reg_totp_secret"] = secret
    session["reg_totp_confirmed"] = False
    session.pop("reg_recovery_codes_h", None)

    otp_uri = pyotp.TOTP(secret).provisioning_uri(name=f"{issuer}:{account}", issuer_name=issuer)
    session.modified = True
    return jsonify({"otp_uri": otp_uri, "secret": secret, "issuer": issuer, "account": account})


@auth_bp.route('/register/twofa_confirm', methods=['POST'])
def register_twofa_confirm():
    if AdminAccount.query.first():
        return jsonify({"error": "Registration closed"}), 403

    if pyotp is None:
        return jsonify({"error": "pyotp library not available"}), 500

    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    secret = session.get("reg_totp_secret")
    if not secret:
        return jsonify({"error": "Start 2FA first"}), 400

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Invalid code"}), 400

    rec_plain = _gen_recovery()
    rec_h = [hash_recovery(c) for c in rec_plain]

    session["reg_totp_confirmed"] = True
    session["reg_recovery_codes_h"] = rec_h
    session.modified = True
    return jsonify({"recovery_codes": rec_plain})


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if AdminAccount.query.first():
        return redirect(url_for('login'))

    setup_token = (current_app.config.get('SETUP_TOKEN') or os.getenv('SETUP_TOKEN', '')).strip()
    require_token = bool(setup_token)

    if request.method == 'POST':
        u = (request.form.get('username') or '').strip()
        p1 = request.form.get('password') or ''
        p2 = request.form.get('password2') or ''
        tok = (request.form.get('setup_token') or '').strip()

        if require_token and not secrets.compare_digest(tok, setup_token):
            flash('Invalid registration token.', 'error')
            return render_template('register.html', require_token=True)

        if not u:
            flash('Username is required.', 'error')
            return render_template('register.html', require_token=require_token)
        if p1 != p2:
            flash('Passwords do not match.', 'error')
            return render_template('register.html', require_token=require_token)
        if len(p1) > 1024:
            flash('Password too long.', 'error')
            return render_template('register.html', require_token=require_token)
        if AdminAccount.query.filter_by(username=u).first():
            flash('That username is already taken.', 'error')
            return render_template('register.html', require_token=require_token)

        try:
            pw_hash = AdminAccount.hash_pw(p1)
            acc = AdminAccount(username=u, password_hash=pw_hash)

            if session.get('reg_totp_confirmed') and session.get('reg_totp_secret'):
                acc.twofa_enabled = True
                acc.totp_secret = session['reg_totp_secret']
                rc_h = session.get('reg_recovery_codes_h') or []
                acc.recovery_codes = '\n'.join(rc_h)

            db.session.add(acc)
            db.session.commit()

        except Exception:
            db.session.rollback()
            current_app.logger.exception("register() failed at commit")
            flash("Internal error while creating the admin. See app.log.", "error")
            return render_template('register.html', require_token=require_token), 500

        for k in ('reg_totp_secret', 'reg_totp_confirmed', 'reg_recovery_codes_h'):
            session.pop(k, None)

        flash(
            'Admin created. Please log in.'
            if len(p1) >= 12
            else 'Admin created. Tip: use 12+ characters for better security.',
            'success',
        )
        return redirect(url_for('login'))

    return render_template('register.html', require_token=require_token)
