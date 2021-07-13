from flask import Flask, render_template, redirect, url_for, request, flash
from flask_security import current_user, login_required, RoleMixin, Security, SQLAlchemyUserDatastore, UserMixin, utils
from flask_admin import Admin
from flask_admin.contrib import sqla
from flask_sqlalchemy import SQLAlchemy
from wtforms.fields import PasswordField
import re

from config import SECRET_KEY, SECURITY_PASSWORD_SALT, SECURITY_PASSWORD_HASH
from config import TEST_PASSWORD, TEST_USER_EMAIL, TEST_ADMIN_EMAIL


# Initialize Flask and set config values
app = Flask(__name__)
app.config['DEBUG']=True
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SECURITY_PASSWORD_HASH'] = SECURITY_PASSWORD_HASH
app.config['SECURITY_PASSWORD_SALT'] = SECURITY_PASSWORD_SALT

# Config database
app.config['DATABASE_FILE'] = 'address_base_db.sqlite'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + app.config['DATABASE_FILE']
app.config['SQLALCHEMY_ECHO'] = True

db = SQLAlchemy(app)

# Create a table to support relationship between Users and Roles
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)


# Role class
class Role(db.Model, RoleMixin):

    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __str__(self):
        return self.name

    def __hash__(self):
        return hash(self.name)


# User class
class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    roles = db.relationship(
        'Role',
        secondary=roles_users,
        backref=db.backref('users', lazy='dynamic')
    )


class Items(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    address = db.Column(db.String(80), unique=True)
    item = db.Column(db.String(255))


# Initialize the SQLAlchemy data store and Flask-Security.
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


@app.before_request
def check_for_admin():
    if request.path.startswith('/admin/'):
        if not current_user.is_authenticated:
            return redirect(url_for('security.login'))


# Executes before the first request is processed.
@app.before_first_request
def before_first_request():
    db.create_all()

    # Create the Roles "admin" and "end-user" -- unless they already exist
    user_datastore.find_or_create_role(name='admin', description='Administrator')
    user_datastore.find_or_create_role(name='end-user', description='End user')

    encrypted_password = utils.hash_password(TEST_PASSWORD)
    if not user_datastore.get_user(TEST_USER_EMAIL):
        user_datastore.create_user(email=TEST_USER_EMAIL, password=encrypted_password)
    if not user_datastore.get_user(TEST_ADMIN_EMAIL):
        user_datastore.create_user(email=TEST_ADMIN_EMAIL, password=encrypted_password)

    # Commit any database changes; the User and Roles must exist before we can add a Role to the User
    db.session.commit()

    # Give one User has the "end-user" role, while the other has the "admin" role. (This will have no effect if the
    # Users already have these Roles.) Again, commit any database changes.
    user_datastore.add_role_to_user(TEST_USER_EMAIL, 'end-user')
    user_datastore.add_role_to_user(TEST_ADMIN_EMAIL, 'admin')
    db.session.commit()

    # # Created db with example Items
    # sample_items = ['Улица 1', 'Улица 3 дом 5', 'Улица 7 дом 3 подьезд 4', 'Улица 11 дом 23 подьезд 14 кв 2б']
    # count = 0
    # for entry in sample_items:
    #     count += 1
    #     item = Items()
    #     item.id = count
    #     item.address = entry
    #     # item.item = "item " + str(count)
    #     item.item = "item "
    #     db.session.add(item)

    db.session.commit()


@app.route('/')
# Flask-Security will display a login form if the user isn't already authenticated.
@login_required
def index():
    return render_template('index.html')


# Customized User model for SQL-Admin
class UserAdmin(sqla.ModelView):

    # Don't display the password on the list of Users
    column_exclude_list = ('password',)

    # Don't include the standard password field when creating or editing a User (but see below)
    form_excluded_columns = ('password',)

    # Automatically display human-readable names for the current and available Roles when creating or editing a User
    column_auto_select_related = True

    # Prevent administration of Users unless the currently logged-in user has the "admin" role
    def is_accessible(self):
        return current_user.has_role('admin')

    # On the form for creating or editing a User, don't display a field corresponding to the model's password field.
    def scaffold_form(self):

        form_class = super(UserAdmin, self).scaffold_form()

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

    # Validation of the form of adding the user
    def validate_form(self, form):
        try:
            if not form.email.data and not form.password2.data and not form.active.data and not form.roles.data:
                return False

            if not form.email.data:
                flash("Enter your email!")
                return False

            if not re.match(r"[a-z\d_.]*@[a-z\d]*.[a-z\d]*", form.email.data):
                flash("Invalid email address!")
                return False

            if not form.password2.data:
                flash("Please fill in the password field!")
                return False

        except AttributeError:
            return super(UserAdmin, self).validate_form(form)

        return super(UserAdmin, self).validate_form(form)


# Customized Role model for SQL-Admin
class RoleAdmin(sqla.ModelView):

    # Prevent administration of Roles unless the currently logged-in user has the "admin" role
    def is_accessible(self):
        return current_user.has_role('admin')

# Customized Role model for SQL-Admin
class ItemsAdmin(sqla.ModelView):

    # Prevent administration of Roles unless the currently logged-in user has the "admin" role
    def is_accessible(self):
        return current_user.has_role('admin')

# Initialize Flask-Admin
admin = Admin(app)

# Add Flask-Admin views for Users, Items and Roles
admin.add_view(UserAdmin(User, db.session))
admin.add_view(RoleAdmin(Role, db.session))
admin.add_view(ItemsAdmin(Items, db.session))


# If running locally, listen on all IP addresses, port 8080
if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int('8080'),
        debug=app.config['DEBUG']
    )
