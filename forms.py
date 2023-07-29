from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.fields import FileField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_wtf.file import FileAllowed


class EditProfileForm(FlaskForm):
    firstname = StringField('First Name', validators=[DataRequired()])
    lastname = StringField('Last Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    gender = SelectField('Gender', choices=[('M', 'Male'), ('F', 'Female')], validators=[DataRequired()])
    photo = FileField('Photo')
    submit = SubmitField('Save Changes')
