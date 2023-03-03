from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, InputRequired
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
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
    comment_text = CKEditorField(label='Comment', validators=[InputRequired()])
    submit = SubmitField(label='Submit Comment')