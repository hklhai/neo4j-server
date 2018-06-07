from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Required
from flask_wtf import FlaskForm


class LoginForm(FlaskForm):
    """
    登录表单
    """
    username = StringField('username', validators=[Required()])
    password = PasswordField('password', validators=[Required()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    """
    注册表单
    """
    username = StringField('username', validators=[Required()])
    password = PasswordField('password', validators=[Required()])
    submit = SubmitField('register')
