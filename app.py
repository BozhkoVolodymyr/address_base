from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import flask_admin as admin
from flask_admin.contrib.sqla import ModelView

from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required

from config import SECRET_KEY, SECURITY_PASSWORD_SALT, TEST_USER_NAME, TEST_USER_EMAIL, TEST_USER_PASSWORD

# Create application
app = Flask(__name__)

# Create dummy secret key so we can use sessions
app.config['SECRET_KEY'] = SECRET_KEY

app.config['SECURITY_PASSWORD_SALT'] = SECURITY_PASSWORD_SALT

# Create in-memory database
app.config['DATABASE_FILE'] = 'address_base_db.sqlite'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + app.config['DATABASE_FILE']
app.config['SQLALCHEMY_ECHO'] = True

# Create database connection object
db = SQLAlchemy(app)


# Models
roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(64))
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))



class Items(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    address = db.Column(db.String(80), unique=True)
    item = db.Column(db.String(255))


# Customized admin interface
class CustomView(ModelView):
    list_template = 'list.html'
    create_template = 'create.html'
    edit_template = 'edit.html'


class UserAdmin(CustomView):
    column_searchable_list = ('name',)
    column_filters = ('name', 'email')


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Create a user to test with
@app.before_first_request
def create_user():
    db.drop_all()
    db.create_all()
    user_datastore.create_user(name=TEST_USER_NAME, email=TEST_USER_EMAIL, password=TEST_USER_PASSWORD)

    # Created db with example Items
    sample_items = ['Улица 1', 'Улица 3 дом 5', 'Улица 7 дом 3 подьезд 4', 'Улица 11 дом 23 подьезд 14 кв 2б']
    count = 0
    for entry in sample_items:
        count += 1
        item = Items()
        item.id = count
        item.address = entry
        # item.item = "item " + str(count)
        item.item = "item "
        db.session.add(item)

    db.session.commit()


@app.route('/')
@login_required
def index():
    return '<a href="/admin/">Click me to get to Admin!</a>'


# Create admin with custom base template
admin = admin.Admin(app, 'Example: Layout-BS3', base_template='layout.html', template_mode='bootstrap3')

# Add views
admin.add_view(CustomView(User, db.session))
admin.add_view(CustomView(Items, db.session))


if __name__ == '__main__':

    # Start app
    app.run(debug=True)
