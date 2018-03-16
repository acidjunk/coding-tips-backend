import datetime
import uuid

import os
from flask import Flask, flash, request, url_for
from flask_admin import helpers as admin_helpers
from flask_admin.actions import action
from flask_admin.contrib.sqla import ModelView
from flask_admin import Admin
from flask_login import UserMixin, current_user
from flask_mail import Mail
from flask_migrate import Migrate, MigrateCommand
from flask_restplus import Api, Resource, fields, marshal_with
from flask_script import Manager
from flask_security import RoleMixin, SQLAlchemyUserDatastore, Security, utils
from flask_sqlalchemy import SQLAlchemy
from markupsafe import Markup
from sqlalchemy.dialects.postgresql.base import UUID
from wtforms import PasswordField

VERSION = '0.1.0'
DATABASE_URI = os.getenv('DATABASE_URI', 'postgres://coding:coding@localhost/coding')

app = Flask(__name__, static_url_path='/static')
app.secret_key = os.getenv('SECRET_KEY', 'TODO:MOVE_TO_BLUEPRINT')

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha512'
app.config['SECURITY_PASSWORD_SALT'] = 'SALTSALTSALT'

# Replace the next six lines with your own SMTP server settings
app.config['SECURITY_EMAIL_SENDER'] = os.getenv('SECURITY_EMAIL_SENDER', 'no-reply@example.com')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER') if os.getenv('MAIL_SERVER') else 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME') if os.getenv('MAIL_USERNAME') else 'no-reply@example.com'
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD') if os.getenv('MAIL_PASSWORD') else 'somepassword'

# More Flask Security settings
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_REGISTER_URL'] = '/admin/create_account'
app.config['SECURITY_LOGIN_URL'] = '/admin/login'
app.config['SECURITY_POST_LOGIN_VIEW'] = '/admin'
app.config['SECURITY_LOGOUT_URL'] = '/admin/logout'
app.config['SECURITY_POST_LOGOUT_VIEW'] = '/admin'
app.config['SECURITY_RESET_URL'] = '/admin/reset'
app.config['SECURITY_CHANGE_URL'] = '/admin/change'
app.config['SECURITY_USER_IDENTITY_ATTRIBUTES'] = ['email', 'username']

# setup DB
db = SQLAlchemy(app)
db.UUID = UUID

api = Api(app)
manager = Manager(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)
admin = Admin(app, name='Coding tips', template_mode='bootstrap3')
mail = Mail(app)


@app.context_processor
def version():
    return dict(version=VERSION)


# Define models
class RoleToUser(db.Model):
    __tablename__ = 'roles_to_users'
    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = db.Column('user_id', db.UUID(as_uuid=True), db.ForeignKey('users.id'))
    role_id = db.Column('role_id', db.UUID(as_uuid=True), db.ForeignKey('roles.id'))


class Role(db.Model, RoleMixin):
    __tablename__ = 'roles'
    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    # __str__ is required by Flask-Admin, so we can have human-readable values for the Role when editing a User.
    def __str__(self):
        return self.name

    # __hash__ is required to avoid the exception TypeError: unhashable type: 'Role' when saving a User
    def __hash__(self):
        return hash(self.name)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    email = db.Column(db.String(255), unique=True)
    username = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary='roles_to_users',
                            backref=db.backref('users', lazy='dynamic'))

    # Human-readable values for the User when editing user related stuff.
    def __str__(self):
        return f'{self.username} : {self.email}'

    # __hash__ is required to avoid the exception TypeError: unhashable type: 'Role' when saving a User
    def __hash__(self):
        return hash(self.email)


class CodingCategory(db.Model):
    __tablename__ = 'coding_categories'
    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = db.Column(db.String(255), unique=True, index=True)

    def __repr__(self):
        return self.name


class CodingCategoryToCodingTip(db.Model):
    __tablename__ = 'coding_categories_to_coding_tips'
    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    coding_category_id = db.Column('coding_category_id', db.UUID(as_uuid=True), db.ForeignKey('coding_categories.id'))
    coding_tip_id = db.Column('coding_tip_id', db.UUID(as_uuid=True), db.ForeignKey('coding_tips.id'))


class CodingTip(db.Model):
    __tablename__ = 'coding_tips'
    id = db.Column(db.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = db.Column(db.String(255), unique=True, index=True)
    content = db.Column(db.Text)
    active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    categories = db.relationship('CodingCategory', secondary='coding_categories_to_coding_tips',
                                 backref=db.backref('coding_tips', lazy='dynamic'))

    def __repr__(self):
        return self.name


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


# define a context processor for merging flask-admin's template context into the
# flask-security views.
@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template=admin.base_template,
        admin_view=admin.index_view,
        h=admin_helpers,
        get_url=url_for
    )


# Executes before the first request is processed.
@app.before_first_request
def before_first_request():
    user_datastore.find_or_create_role(name='admin', description='God mode!')
    user_datastore.find_or_create_role(name='moderator', description='Can moderate other users content')
    user_datastore.find_or_create_role(name='operator', description='Can create and block users')

    # Create a default user
    encrypted_password = utils.hash_password('acidjunk@gmail.com')
    if not user_datastore.get_user('acidjunk@gmail.com'):
        user_datastore.create_user(email='acidjunk@gmail.com', password=encrypted_password)
        db.session.commit()
        user_datastore.add_role_to_user('acidjunk@gmail.com', 'admin')
        db.session.commit()


class UserAdminView(ModelView):
    # Don't display the password on the list of Users
    column_exclude_list = list = ('password',)

    # Don't include the standard password field when creating or editing a User (but see below)
    form_excluded_columns = ('password',)

    # Automatically display human-readable names for the current and available Roles when creating or editing a User
    column_auto_select_related = True

    # Prevent administration of Users unless the currently logged-in user has the "admin" role
    def is_accessible(self):
        if 'admin' in current_user.roles:
            return True

    # On the form for creating or editing a User, don't display a field corresponding to the model's password field.
    # There are two reasons for this. First, we want to encrypt the password before storing in the database. Second,
    # we want to use a password field (with the input masked) rather than a regular text field.
    def scaffold_form(self):
        # Start with the standard form as provided by Flask-Admin. We've already told Flask-Admin to exclude the
        # password field from this form.
        form_class = super(UserAdminView, self).scaffold_form()

        # Add a password field, naming it "password2" and labeling it "New Password".
        form_class.password2 = PasswordField('New Password')
        return form_class

    # This callback executes when the user saves changes to a newly-created or edited User -- before the changes are
    # committed to the database.
    def on_model_change(self, form, model, is_created):
        # If the password field isn't blank...
        if len(model.password2):
            # ... then encrypt the new password prior to storing it in the database. If the password field is blank,
            # the existing password in the database will be retained.
            model.password = utils.hash_password(model.password2)


class RolesAdminView(ModelView):

    # Prevent administration of Roles unless the currently logged-in user has the "admin" role
    def is_accessible(self):
        if 'admin' in current_user.roles:
            return True


class CodingTipAdminView(ModelView):
    column_list = ['id', 'name', 'active', 'created_on']
    column_default_sort = ('name', True)
    column_filters = ('active', )
    column_searchable_list = ('name', )

    def is_accessible(self):
        if 'admin' in current_user.roles:
            return True


admin.add_view(CodingTipAdminView(CodingTip, db.session))
admin.add_view(UserAdminView(User, db.session))
admin.add_view(RolesAdminView(Role, db.session))

if __name__ == '__main__':
    manager.run()
