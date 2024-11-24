from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, URL, InputRequired


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = TextAreaField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class RegisterForm(FlaskForm):
    email = StringField(label='Email', validators=[InputRequired()])
    password = PasswordField(label='Password', validators=[InputRequired()])
    name = StringField(label='Name', validators=[InputRequired()])
    submit = SubmitField(label='Sign Me Up!')

class LogInForm(FlaskForm):
    email = StringField(label='Email', validators=[InputRequired()])
    password = PasswordField(label='Password', validators=[InputRequired()])
    submit = SubmitField(label='Let Me In!')

class CommentForm(FlaskForm):
    comment_text = TextAreaField(label='Comment', validators=[InputRequired()])
    submit = SubmitField(label='Submit Comment')

class ContactMeForm(FlaskForm):
    name = StringField(label="Name", validators=[InputRequired()])
    email = StringField(label="Email", validators=[InputRequired()])
    phone = IntegerField(label="phoneNumber", validators=[InputRequired()])
    message = TextAreaField(label="Message", validators=[InputRequired()])
    submit = SubmitField(label='Send')
