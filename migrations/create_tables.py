from flask import Flask
from app.models import db, User, Password

def create_tables():
    """
    Creates all database tables if they don't exist.
    This can be run as a standalone script:
    
    python migrations/create_tables.py
    """
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_analyzer.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    
    with app.app_context():
        db.create_all()
        print("Database tables created successfully:")
        for table in db.metadata.tables.keys():
            print(f" - {table}")

if __name__ == '__main__':
    create_tables() 