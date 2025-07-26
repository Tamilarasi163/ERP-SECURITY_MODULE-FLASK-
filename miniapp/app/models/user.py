import datetime
from app import db

from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(150),unique=True,nullable=False)
    email=db.Column(db.String(150),nullable=False)
    password_hash=db.Column(db.String(500),nullable=False)
    is_verified=db.Column(db.Boolean,default=False)
    
    otps = db.relationship('OTP', back_populates='user', cascade="all, delete-orphan")
    
    
    # otps=db.relationship('OTP',backref='user',lazy=True)

    def set_password(self,password):
       self.password_hash=generate_password_hash(password)
    
    def check_password(self,password):
        return check_password_hash(self.password_hash,password)
 
    def __repr__(self):
        return f"<User {self.username}>"
    
    
# class OTP(db.Model):
#     id=db.Column(db.Integer,primary_key=True)
#     code=db.Column(db.String(6),nullable=False)
#     created_at=db.Column(db.DateTime,default=datetime.utcnow)
#     expires_at=db.Column(db.DateTime,default=lambda: datetime.utcnow()+datetime.timedelta(minutes=10))
#     is_used=db.Column(db.Boolean,default=False)
    
#     user_id=db.Column(db.Integer,db.ForeignKey('User.id'),nullable=False)
    
#     def __repr__(self):
#         return f"<OTP {self.id}>,{self.code}"
    
    
    # class OTP(db.Model):
    #     __tablename__ = 'otp'

    #     id = db.Column(db.Integer, primary_key=True)
    #     otp_code = db.Column(db.String(6), nullable=False)
    #     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    #     created_at = db.Column(db.DateTime, default=datetime.utcnow)
    #     expires_at = db.Column(db.DateTime, nullable=False)
    #     is_used = db.Column(db.Boolean, default=False)

    #     user = db.relationship('User', back_populates='otps')
        

    
    
    


