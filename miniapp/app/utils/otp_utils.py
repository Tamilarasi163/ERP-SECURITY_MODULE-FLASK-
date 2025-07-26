import random
from datetime import datetime, timedelta
from app import db
from app.models.otp import OTP

def generate_and_store_otp(user):
    otp_code = str(random.randint(100000, 999999))
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    otp_entry = OTP(
        otp_code=otp_code,
        user_id=user.id,
        expires_at=expires_at
    )

    db.session.add(otp_entry)
    db.session.commit()
    return otp_code

def validate_otp(user, submitted_otp):
    now = datetime.utcnow()

    otp_entry = OTP.query.filter_by(
        user_id=user.id,
        otp_code=submitted_otp,
        is_used=False
    ).filter(OTP.expires_at > now).first()

    if otp_entry:
        otp_entry.is_used = True
        db.session.commit()
        return True
    return False
