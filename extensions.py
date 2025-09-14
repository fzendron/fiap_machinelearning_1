from sqlalchemy import create_engine, MetaData, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()