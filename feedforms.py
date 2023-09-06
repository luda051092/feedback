from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.fields.html5 import EmailField
from wtforms.validators import InputRequired, Email, Length


class UserForm(FlaskForm):
    """Form for user register"""
    username = StringField("Username", validators=[InputRequired(), Length(min=3 , max=20)])
    password = PasswordField("Password", validators=[InputRequired()])
    email = EmailField("Email", validators=[InputRequired(), Length(min=1 , max=50), Email(message='Need a valid email address')])
    first_name = StringField("First Name", validators=[InputRequired(), Length(min=1 , max=30)])
    last_name = StringField("Last Name", validators=[InputRequired(), Length(min=1 , max=30)])

class UserLoginForm(FlaskForm):
    """Form for user login"""
    username = StringField("Username", validators=[InputRequired(), Length(min=3 , max=20)])
    password = PasswordField("Password", validators=[InputRequired()])

class FeedbackForm(FlaskForm):
    """Feedback form"""
    title = StringField("Title", validators=[InputRequired() , Length(min=1 , max=100)])
    content = TextAreaField("Content", validators=[InputRequired()])

class PasswordEmailForm(FlaskForm):
    """email form for resetting password"""
   email = EmailField("Email" , validators=[InputRequired() , Length(min=1 , max=50) , Email(message'Need a valid email address')])
 
class ResetPasswordForm(FlaskForm):
    """Reset password form"""
    password = PasswordField(" New Password", validators=[InputRequired()])