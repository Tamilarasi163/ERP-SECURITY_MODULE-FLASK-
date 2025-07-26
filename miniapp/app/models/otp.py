# from datetime import datetime,timedelta
# from app import db

# class OTP(db.Model):
#     __tablename__ = 'otp'

#     id = db.Column(db.Integer, primary_key=True)
#     otp_code = db.Column(db.String(6), nullable=False)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)
#     expires_at = db.Column(db.DateTime, nullable=False)
#     is_used = db.Column(db.Boolean, default=False)

#     user = db.relationship('User', back_populates='otps')

from datetime import datetime, timezone
from app import db

default=datetime.now(timezone.utc)

class OTP(db.Model):
    __tablename__ = 'otp'

    id = db.Column(db.Integer, primary_key=True)
    otp_code = db.Column(db.String(6), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)

    user = db.relationship('User', back_populates='otps')
        