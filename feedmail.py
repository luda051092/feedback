from flask_mail import Mail
from secret import *

def config_mail(app):
    """config flask mail"""
    app.comfig.update(
        MAIL_SERVER='stmp.yahoo.com', 
        MAIL_PORT=565,
        MAIL_USE_SSL=True, 
        MAIL_USERNAME = MAIL_USERNAME,
        MAIL_PASSWORD = MAIL_PASSWORD
    )

    mail = Mail(app)

    return mail