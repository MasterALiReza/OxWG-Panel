"""
OxWg Panel - Admin Management Blueprint (admin_bp)
=================================================
Handles admin password change, renaming, and 2FA configuration.
Branding: 2FA issuer "OxWg Panel", label "OxWg-Panel:{username}".
"""
import json
import secrets
from flask import Blueprint, request, jsonify, session, current_app
from flask_login import login_required, current_user

try:
    import pyotp
except ImportError:
    pyotp = None

from core.extensions import db
from core.crypto import _gen_recovery, hash_recovery
from models import AdminAccount, Admin2FA
from auth import admin_required

admin_bp = Blueprint('admin_bp', __name__)


@admin_bp.get('/api/admin')
@login_required
def admin_status():
    acc = AdminAccount.query.first()
    if not acc:
        return jsonify(error="no_admin"), 404
    rc = 0
    if (acc.recovery_codes or '').strip():
        rc = len([x for x in acc.recovery_codes.splitlines() if x.strip()])
    return jsonify({
        "username": acc.username,
        "twofa_enabled": bool(acc.twofa_enabled),
        "recovery_count": rc,
    }), 200


@admin_bp.post('/api/admin/password')
@login_required
def admin_change_password():
    data = request.get_json(silent=True) or {}
    cur = (data.get('current') or '').strip()
    new = (data.get('new') or '').strip()
    if not new:
        return jsonify(error="empty_new"), 400
    acc = AdminAccount.query.first()
    if not acc or not acc.verify_pw(cur):
        return jsonify(error="bad_current"), 400
    acc.password_hash = AdminAccount.hash_pw(new)
    db.session.commit()
    return jsonify(ok=True)


@admin_bp.post('/api/admin/rename')
@login_required
def admin_rename():
    data = request.get_json(silent=True) or {}
    newu = (data.get('username') or '').strip()
    if not newu:
        return jsonify(error="empty_username"), 400
    if AdminAccount.query.filter_by(username=newu).first():
        return jsonify(error="taken"), 400
    acc = AdminAccount.query.first()
    if not acc:
        return jsonify(error="no_admin"), 404
    acc.username = newu
    db.session.commit()
    return jsonify(ok=True)


@admin_bp.route('/api/admin/twofa_begin', methods=['POST'])
@login_required
def twofa_begin():
    if pyotp is None:
        return jsonify(error="pyotp library not available"), 500

    username = getattr(current_user, 'username', 'admin')
    secret = pyotp.random_base32()
    session['twofa_pending_secret'] = secret
    session.modified = True
    label = f"OxWg-Panel:{username}"
    issuer = "OxWg Panel"
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=label, issuer_name=issuer)
    return jsonify(secret=secret, otp_uri=otp_uri), 200


@admin_bp.route('/api/admin/twofa_confirm', methods=['POST'])
@login_required
def twofa_confirm():
    try:
        data = request.get_json(silent=True) or {}
        otp = (data.get('otp') or '').strip()
        username = getattr(current_user, 'username', 'admin')
        pending = session.get('twofa_pending_secret')

        if not pending:
            return jsonify(error='No 2FA setup in progress'), 400
        if not (otp.isdigit() and len(otp) == 6):
            return jsonify(error='Invalid code'), 400

        if pyotp is None:
            return jsonify(error='pyotp library not available'), 500

        totp = pyotp.TOTP(pending)
        if not totp.verify(otp, valid_window=1):
            return jsonify(error='Incorrect or expired code'), 400

        recovery_plain = _gen_recovery()
        rec_h = [hash_recovery(c) for c in recovery_plain]

        acc = AdminAccount.query.filter_by(username=username).first()
        if acc:
            acc.twofa_enabled = True
            acc.totp_secret = pending
            acc.recovery_codes = '\n'.join(rec_h)
            db.session.commit()

        try:
            rec = Admin2FA.query.filter_by(username=username).first()
            if not rec:
                rec = Admin2FA(username=username, enabled=False)
                db.session.add(rec)
            rec.enabled = True
            rec.recovery_hashes = json.dumps(rec_h)
            db.session.commit()
        except Exception:
            pass

        session.pop('twofa_pending_secret', None)
        session.modified = True

        return jsonify(ok=True, recovery_codes=recovery_plain), 200

    except Exception:
        current_app.logger.exception("twofa_confirm failed")
        return jsonify(error='Internal error while enabling 2FA'), 500


@admin_bp.route('/api/admin/twofa_disable', methods=['POST'])
@login_required
def twofa_disable():
    try:
        username = getattr(current_user, 'username', 'admin')

        acc = AdminAccount.query.filter_by(username=username).first()
        if acc:
            acc.twofa_enabled = False
            acc.totp_secret = None
            acc.recovery_codes = ''
            db.session.commit()

        try:
            rec = Admin2FA.query.filter_by(username=username).first()
            if rec:
                rec.enabled = False
                rec.secret_enc = None
                rec.recovery_hashes = json.dumps([])
                db.session.commit()
        except Exception:
            pass

        session.pop('twofa_pending_secret', None)
        session.modified = True

        return jsonify(ok=True), 200

    except Exception:
        current_app.logger.exception("twofa_disable failed")
        return jsonify(error='Internal error while disabling 2FA'), 500
