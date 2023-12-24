from flask import Flask
from controllers.auth_controller import auth_blueprint
from models.user_model import db
from flask_sslify import SSLify
from flask_talisman import Talisman

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
app.register_blueprint(auth_blueprint)


# Enforce HTTPS using the Flask SSLify extension
# Enforce HTTPS
sslify = SSLify(app)
# Configure session cookies for secure transmission
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
#--------------------------


# Add security headers with Flask-Talisman
# Configure Content Security Policy (CSP)
csp = {
    'script-src': ["'self'", "'unsafe-inline'"],
    'img-src': "'self'"
}
talisman = Talisman(app, content_security_policy=csp)
#---------------------------


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
