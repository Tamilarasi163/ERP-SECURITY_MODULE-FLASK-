from flask import Config, Flask
from flask_migrate import Migrate
from app.extensions import db, mail  
from app.config import Config 

migrate = Migrate() 

def create_app():
    app = Flask(__name__)
    
    app.config.from_object(Config)
    
    db.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db) 
    
    from app.auth import auth_bp
    
    app.register_blueprint(auth_bp, url_prefix="/")
  
    return app