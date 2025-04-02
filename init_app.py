#!/usr/bin/env python
"""
Initialization script for AI-Enhanced Password Analyzer
This script sets up the application by creating the database and necessary tables.
"""

import os
from flask import Flask
from app.models import db, User, Password

def init_app():
    """Initialize the application and database"""
    print("Initializing AI-Enhanced Password Analyzer...")
    
    # Create application instance
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///password_analyzer.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize database
    db.init_app(app)
    
    with app.app_context():
        # Create all tables
        db.create_all()
        print("Database tables created successfully:")
        for table in db.metadata.tables.keys():
            print(f" - {table}")
        
        print("\nApplication initialized successfully!")
        print("\nRun the following command to start the application:")
        print("    python app.py")
        print("\nThen open your browser and visit: http://127.0.0.1:5000")

if __name__ == '__main__':
    init_app() 