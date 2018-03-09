'''
NOT DEBUGGED!

This was a script I wrote for my husband and my wedding website. This was my FIRST website. Please excuse the mess. I'm workin' on it. 

Basically Flask website that allows users to register, login, renew their passwords (I didn't provide that option in the final version tho), RSVP, check organization details, look at our gallery, have discussion with other guests, and of course logout. 

'''

from flask import Flask
from flask import request, render_template, flash, url_for, redirect, session

from flask_login import LoginManager
from flask_mail import Mail, Message
from passlib.hash import sha256_crypt
import gc
from functools import wraps
import pytz
from itsdangerous import URLSafeTimedSerializer
from flask_login import login_required
from sqlalchemy import text
from datetime import datetime

#import models 
from wedd_app_models import engine, db_session, Base, db, User, RSVP, Discussion, Reply, app


#import forms
from wedd_forms import RegistrationForm, EmailForm, PasswordForm, RSVPForm

#import translation stuff
from flask.ext.babel import Babel

Base.query = db_session.query_property()
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'

app.secret_key = "secret_key"
app.config['MAIL_SERVER']='exemail@gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_DEFAULT_SENDER'] = 'exemail@gmail.com'
app.config['MAIL_USERNAME'] = 'exemail@gmail.com'
app.config['MAIL_PASSWORD'] = 'password'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['SECURITY_PASSWORD_SALT'] = 'security_password_salt'

babel = Babel(app)

from config import LANGUAGES
@babel.localeselector
def get_locale():
    return request.accept_languages.best_match(LANGUAGES.keys())
    
Base.metadata.create_all(engine)
db._model_changes={}
db.commit()

mail = Mail(app)
#RSVPform = model_form(RSVP, Form)
#RSVP_form = model_form(RSVPForm, Form) 

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=86400):
    try:
        serializer = URLSafeTimedSerializer(app.secret_key)
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age = expiration
            )
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    return email

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html = template,
        sender=app.config['MAIL_DEFAULT_SENDER']
        )
    mail.send(msg)

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("You need to login first")
            return redirect(url_for('login'))
    return wrap
        
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
    
@app.errorhandler(404)
def error404(error):
    return render_template('error404.html', error = error)

@app.errorhandler(500)
def error500(error):
    return render_template('error500.html', error = error)

@app.errorhandler(405)
def error405(error):
    #method is not allowed
    return render_template('error405.html', error=error)

@app.route('/confirm/<token>')
@login_required
def confirm_email(token):
    username = session['username']
    user = db.query(User).filter_by(username=username).one()
    if user.confirmed:
        flash('Account already confirmed.', 'success')
        return redirect(url_for('home'))
    else: 
        email = confirm_token(token)
        #user = User.query.filter_by(email=current_user.email).first_or_404()
        if user.email == email:
            user.confirmed = True
            user.confirmed_on = datetime.utcnow()
            db._model_changes = {}
            db.commit()       
            flash('You have confirmed your account. Thanks!', 'success')
        return redirect(url_for('home'))
    
@app.route('/password_reset', methods=['GET','POST'])
def reset():
    form = EmailForm(request.form)
    if request.method == "POST":
        email = form.email.data
        exist = db.query(User).filter_by(email=email).all()
        if len(exist) == 1:
            user = db.query(User).filter_by(email=email).first()
            if user.confirmed:
                subject = "Password reset requested"
                serializer = URLSafeTimedSerializer(app.secret_key)
                token = serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])
                
                recover_url = url_for('reset_with_token', token=token, _external = True)
                
                html = render_template('recover.html', recover_url=recover_url)
                
                send_email(user.email, subject, html)
                flash('A link to reset your password has been emailed to you. Please check your spam folder.')
            else:
                flash("I'm sorry. Your email has not yet been confirmed. Please contact Aislyn or Thomas via email directly (see bottom of page)")
        else:
            flash("Invalid Email")
        return redirect(url_for('home'))
    else:
        return render_template('reset.html', form=form)
    
@app.route('/reset/<token>', methods=['GET','POST'])
def reset_with_token(token, expiration=86400):
    try:
        serializer = URLSafeTimedSerializer(app.secret_key)
        email = serializer.loads(
        token,
        salt=app.config['SECURITY_PASSWORD_SALT'],
        max_age = expiration
        )
    except:
        flash('The reset passoword link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    form = PasswordForm(request.form)
    
    if request.method == "POST" and form.validate():
        user = db.query(User).filter_by(email=email).first()
        user.password = sha256_crypt.encrypt((str(form.password.data)))
        db._model_changes = {}
        db.commit()
        flash('Your password has been changed')
        return redirect(url_for('login'))
    return render_template('reset_with_token.html', form=form, token=token)

@app.route('/register/', methods=['GET','POST'])
def register():
    try:
        form = RegistrationForm(request.form)
        
        if request.method == "POST" and form.validate():
            username = form.username.data
            email = form.email.data
            if ' ' in username:
                flash("Invalid username. Please remove spaces")
                return(redirect(url_for('register')))
            password = sha256_crypt.encrypt((str(form.password.data)))
            data = db.query(User).from_statement(text("SELECT * FROM users where username=:username")).params(username=username).all()
            if len(data) != 0:
                flash("That username is already taken, please choose another")
                return(redirect(url_for('register')))
            data_email = db.query(User).from_statement(text("SELECT * FROM users where email=:email")).params(email=email).all()
            if len(data_email) != 0:
                flash("That email is already taken, please use another")
                return(redirect(url_for('register')))
            user = User(username, password, email, confirmed=False)
            db.add(user)
            db._model_changes = {}
            db.commit()
            #token = generate_confirmation_token(user.email)
            #confirm_url = url_for('confirm_email',token=token, _external=True)
            #html = render_template('activate.html',confirm_url = confirm_url)
            #subject = "Please confirm your email"
            session['logged_in'] = True
            session['username'] = user.username
            #send_email(user.email, subject, html)
            
            ##login_user(user)
            
            #flash('A confirmation email has been sent to you. Please check your junk mail/spam folder and mark the email as safe/not junk. The link will be valid for 24 hours', 'success')
            #return render_template('wedd_confirmemail.html')
            return redirect(url_for('home'))
        
        return render_template("weddregister.html",form=form)
            
    except Exception as e:
        #done debugging: get this out
        return str(e)

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out")
    gc.collect()
    return redirect(url_for('home'))

@app.route('/login', methods=['GET','POST'])
def login():
    error=None

    try:
        if request.method=="POST":
            loginname = request.form['username']
            if '@' in loginname:
                data = db.query(User).from_statement(text("SELECT * FROM users where email=:username")).params(username=loginname).all()
            else: 
                data = db.query(User).from_statement(text("SELECT * FROM users where username=:username")).params(username=loginname).all()
            if len(data) ==0:
                error = "Invalid credentials. Try again."
                return render_template("weddlogin.html", error = error)
            else:
                data=data[0]
                if  sha256_crypt.verify(request.form['password'],data.password):
                    session['logged_in']=True
                    session['username']= data.username
                    flash("You are now logged in")
                    return redirect(url_for('home'))
                else:
                    error = "Invalid credentials. Try again."
        return render_template("weddlogin.html", error=error)
    except Exception as e:
        return render_template("weddlogin.html", error=error)
        

@app.route("/")
def home():
    error = None
    try:
        if session['logged_in']:
            username = session['username']
            #user = db.query(User).filter_by(username=username).one()
            #if not user.confirmed:
                #token = generate_confirmation_token(user.email)
                #confirm_url = url_for('confirm_email',token=token, _external=True)
                #html = render_template('activate.html',confirm_url = confirm_url)
                #subject = "Please confirm your email"
                #send_email(user.email, subject, html)
                #flash('So that you can be updated on developments of our wedding and so that you can change your password, please confirm your email. A confirmation email has been sent to you. Please check your junk mail/spam folder, mark the email as safe/not junk, and validate your email with the provided link. Thanks!', 'success')
                
            return render_template("weddhome.html", username=username)
        else:
            return render_template("weddhome.html")
    except Exception as e:
        return render_template("weddhome.html", error=error)

@app.route("/plan")
@login_required
def plan():
    return render_template("weddplan.html")

@app.route("/convo", methods=["GET","POST"])
@login_required
def convo():
    #try: 
    username = session['username']
    user = db.query(User).filter_by(username=username).one()
    user_id = str(user.id)
    date_raw = datetime.now(pytz.utc)
    date = date_raw.strftime("%Y-%m-%d  %H:%M UTC")
    if request.method == "POST":
        comment = request.form.get('comment')
        commentdata = Discussion(user_id = user_id,username=username,comment=comment)
        db.add(commentdata)
        db._model_changes={}
        db.commit()
        ##email other users the comment - get the discussion going
        #users_confirmed = db.query(User).filter_by(confirmed=True).all()
        #subject = username+" has posted in Thomas and Aislyn's wedding page"
        #login_url = url_for('convo', _external=True)
        #for user_data in users_confirmed:
            #if user_data.username != username:
                #html = render_template("comment_posted.html", username_commenter = username, username_email = user_data.username, comment = comment, login_url = login_url)
                #send_email(user_data.email, subject, html)
        #send_email(users_confirmed,subject,html)
        all_comments = db.query(Discussion.id, Discussion.user_id, Discussion.username, Discussion.date, Discussion.comment).all()
        all_replies = db.query(Reply.id, Reply.parent_id, Reply.user_id, Reply.username, Reply.date, Reply.reply).all()
        comments_replies = []
        for i in range(len(all_comments)):
            comm = []
            comment_id = all_comments[i][0]
            comm.append(all_comments[i])
            for j in range(len(all_replies)):
                if comment_id == all_replies[j][1]:
                    comm.append([all_replies[j]])
            comments_replies.append(comm)
        return redirect(url_for('convo'))
    else:
        all_comments = db.query(Discussion.id, Discussion.user_id, Discussion.username, Discussion.date, Discussion.comment).all()
        all_replies = db.query(Reply.id, Reply.parent_id, Reply.user_id, Reply.username, Reply.date, Reply.reply).all()
        comments_replies = []
        for i in range(len(all_comments)):
            comm = []
            comment_id = all_comments[i][0]
            comm.append(all_comments[i])
            for j in range(len(all_replies)):
                if comment_id == all_replies[j][1]:
                    comm.append([all_replies[j]])
            comments_replies.append(comm)
        return render_template("weddquestions5.html", comments_replies = comments_replies)
    #except:
        #flash("We're sorry. It appears an error has occurred. If this problem persists, please write Aislyn or Thomas.", 'danger')
        #return redirect(url_for('convo'))

@app.route('/_postreply', methods=['GET','POST'])
@login_required
def _postreply():
    reply_text = request.form['replycomment']
    parent_id = request.form['submit']
    parent_id = list(filter(str.isdigit,parent_id))
    parent_id=int(''.join(str(i) for i in parent_id))
    username = session['username']
    user = db.query(User).filter_by(username=username).one()
    user_id = str(user.id)
    reply_data = Reply(parent_id=parent_id,user_id=user_id,username=username,reply=reply_text)
    db.add(reply_data)
    db._model_changes={}
    db.commit()
    ##collecting information to send notification email to writer of head comment
    #username2 = username
    #comment_data = db.query(Discussion).filter_by(id=parent_id).one()
    #username1 = comment_data.username
    #username1_info = db.query(User).filter_by(username=username1).one()
    #username1_email = username1_info.email
    #if username1_info.confirmed and username2 != username1:
        #login_url = url_for('convo', _external=True)
        #subject = username2+" responded to your comment"
        #html = render_template('comment_response.html', username1 = username1, username2 = username2, login_url = login_url, text=reply_text)
        #send_email(username1_email, subject, html)
    ##collecting information to send notification email to writer of previous reply
    #reply_data = db.query(Reply).filter_by(reply=reply_text).one()
    #reply_data_id = reply_data.id
    #if reply_data_id > 0:
        #reply_parent = reply_data_id-1
        #reply_parent_data = db.query(Reply).filter_by(id=reply_parent).one()
        #username3=reply_parent_data.username
        #username3_info = db.query(User).filter_by(username=username3).one()
        #username3_email = username3_info.email
        ##don't want to send emails if they are responding to their own reply or two emails if the parent_reply is also written by the person who wrote the original comment 
        #if username3_info.confirmed and username3 != username2 and username3 != username1:
            #login_url = url_for('convo', _external=True)
            #subject = username2+" responded to your comment"
            #html = render_template('comment_response.html', username1 = username3, username2 = username2, login_url = login_url, text = reply_text)
            #send_email(username3_email, subject, html)
    return redirect(url_for('convo'))

@app.route('/ourstory', methods = ['GET','POST'])
@login_required
def story():
    return render_template('weddstory.html')
    
@app.route('/rsvp', methods= ['GET','POST'])
@login_required
def rsvp():
    rsvplabels = ('Username:', 'Date:', 'RSVP:', 'Name of party:', 'Phone:', 'Preferred Email:', 'Number of people in your party:', 'Names of people in your party:', 'Accommodation preferences:', 'Number and type of vehicles:', 'Day of arrival:', 'Time of arrival:', 'Day of departure:', 'Time of departure:', 'Travel plans:', 'Food preferences:', 'Activity preferences:', 'Your comments:')
    rsvplabels = [x.upper() for x in rsvplabels]
    username = session['username']
    user = db.query(User).filter_by(username=username).one()
    user_id = str(user.id)
    usr_rsvp = db.query(RSVP).filter_by(username=username).all()
    if len(usr_rsvp) == 0: 
        today = datetime.now(pytz.utc).strftime("%Y-%m-%d  %H:%M (utc)")
        add_rsvp = RSVP(user_id = user_id, username=username, date=today)
        db.add(add_rsvp)
        Base.metadata.create_all(engine)
        db._model_changes={}
        db.commit()
    usr = db.query(RSVP).filter_by(username=username).one()
    form = RSVPForm(obj=usr)
    if request.method == 'POST':
        today = datetime.now(pytz.utc).strftime("%Y-%m-%d  %H:%M (utc)")
        rsvp_response = request.form['rsvpresponse'];
        party_name = request.form['party_name']
        phone = request.form['phone']
        email = request.form['email']
        numppl = request.form['numppl']
        numcars = request.form['numcars']
        namesppl = request.form['namesppl']
        accommodation = request.form['accommodation']
        dayarrival = request.form['dayarrival']
        timearrival = request.form['timearrival']
        daydepart = request.form['daydepart']
        timedepart = request.form['timedepart']
        carpool = request.form['carpool']
        foodpref = request.form['foodpref']
        activities = request.form['activities']
        comments = request.form['comments']
        usr_rsvp = db.query(RSVP).filter_by(username=username).one()
        usr_rsvp.date = datetime.now(pytz.utc).strftime("%Y-%m-%d  %H:%M (utc)")
        usr_rsvp.rsvpresponse = rsvp_response
        usr_rsvp.party_name = party_name
        usr_rsvp.phone = phone 
        usr_rsvp.email = email
        usr_rsvp.numppl = numppl
        usr_rsvp.numcars = numcars
        usr_rsvp.namesppl = namesppl
        usr_rsvp.accommodation = accommodation
        usr_rsvp.dayarrival = dayarrival
        usr_rsvp.timearrival = timearrival
        usr_rsvp.daydepart = daydepart
        usr_rsvp.timedepart = timedepart
        usr_rsvp.carpool = carpool
        usr_rsvp.foodpref = foodpref
        usr_rsvp.activities = activities
        usr_rsvp.comments = comments
        Base.metadata.create_all(engine)
        db._model_changes={}
        db.commit()
        usr_rsvp_list = db.query(RSVP.username, RSVP.date, RSVP.rsvpresponse, RSVP.party_name, RSVP.phone, RSVP.email, RSVP.numppl, RSVP.namesppl, RSVP.accommodation, RSVP.numcars, RSVP.dayarrival, RSVP.timearrival, RSVP.daydepart, RSVP.timedepart, RSVP.carpool, RSVP.foodpref, RSVP.activities, RSVP.comments).filter_by(username=username).all()
        usr_rsvp_list = list(usr_rsvp_list[0])
        usrdata_labels = zip(rsvplabels,usr_rsvp_list)
        times_submitted=1
        return render_template('weddrsvp_edittable.html', form=form, username=username, usrdata_labels = usrdata_labels, times_submitted=times_submitted)
        #return jsonify(usr_rsvp)
    else:
        usr_rsvp = db.query(RSVP).filter_by(username=username).all()
        usr_rsvp_list = db.query(RSVP.username, RSVP.date, RSVP.rsvpresponse, RSVP.party_name, RSVP.phone, RSVP.email, RSVP.numppl, RSVP.namesppl, RSVP.accommodation, RSVP.numcars, RSVP.dayarrival, RSVP.timearrival, RSVP.daydepart, RSVP.timedepart, RSVP.carpool, RSVP.foodpref, RSVP.activities, RSVP.comments).filter_by(username=username).all()
        usr_rsvp_list = list(usr_rsvp_list[0])
        usrdata_labels = zip(rsvplabels,usr_rsvp_list)
        times_submitted=1
        return render_template('weddrsvp_edittable.html', form=form, username=username, usrdata_labels = usrdata_labels, times_submitted=times_submitted)



@app.route('/registry')
@login_required
def registry():
    return render_template("weddregistry.html")

if __name__ == "__main__":
    app.run(host='0.0.0.0',debug=True)
