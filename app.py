from flask import Flask, render_template, request, redirect, url_for,flash, jsonify  
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from models import User, db, Tweet,BullyingMessage,Report
from forms import EditProfileForm
from datetime import datetime 
from werkzeug.utils import secure_filename
import os


app = Flask(__name__)
app.secret_key = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'static/photo'  # Set the upload folder for photos


db.init_app(app)
bcrypt = Bcrypt(app)
with app.app_context():
    db.create_all()


# Add enumerate to the Jinja2 environment
app.jinja_env.globals.update(enumerate=enumerate)


login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Welcome Page
@app.route('/')
def index():
    return render_template('index.html')


# admin login
@login_manager.user_loader
def load_user(user_id):
    # Check if admin user exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        # Create admin user if not exists
        admin = User(
            id=1,
            firstname='Admin',
            lastname='Admin',
            email='admin@example.com',
            username='admin',
            password_hash=bcrypt.generate_password_hash('password').decode('utf-8'),
            gender='N/A',
            birthdate='N/A',
            is_active=True,
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit() 
    return User.query.get(int(user_id))


# Signup View
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('login'))
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirmpassword = request.form['confirmpassword']
        gender = request.form['gender']
        birthdate = request.form['birthdate']
        is_admin = True if request.form.get('is_admin') else False  # Get the value of is_admin field
        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        if existing_user or existing_email:
            error = 'Username or email already exists'
            return render_template('signup.html', error=error)
        elif password != confirmpassword:
            error = 'Passwords do not match'
            return render_template('signup.html', error=error)
        else:
            user = User(firstname=firstname, lastname=lastname, email=email, username=username, gender=gender, birthdate=birthdate, is_admin=is_admin)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created!', 'success')
            login_user(user)
            return redirect(url_for('login'))
    else:
        return render_template('signup.html')


@app.route('/homepage')
@login_required
def homepage():
    tweets = Tweet.query.order_by(Tweet.timestamp.desc()).all()
    tweets = []
    for friend in current_user.friends:
        tweets += friend.tweets
    tweets += current_user.tweets
    tweets.sort(key=lambda t: t.timestamp, reverse=True)
    return render_template('homepage.html', tweets=tweets)


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/add_friend', methods=['GET', 'POST'])
@login_required
def add_friend():
    if request.method == 'POST':
        username = request.form['username']
        friend = User.query.filter_by(username=username).first()
        if friend:
            if friend.is_blocked:
                error = 'This user is blocked and cannot be added as a friend.'
                return render_template('add_friend.html', error=error)
            if friend not in current_user.friends:
                current_user.friends.append(friend)
                db.session.commit()
                return redirect(url_for('homepage'))
            else:
                error = 'This user is already in your friends list.'
                return render_template('add_friend.html', error=error)
        else:
            error = 'User does not exist.'
            return render_template('add_friend.html', error=error)
    else:
        return render_template('add_friend.html')
        

@app.route('/friends')
@login_required
def friends():
    friends = current_user.friends.all()
    return render_template('friend_list.html', friends=friends)


@app.route('/search_friends', methods=['GET', 'POST'])
@login_required
def search_friends():
    if request.method == 'POST':
        search_query = request.form['search_query']
        friends = User.query.filter(User.username.startswith(search_query)).all()

        friend_data = []
        for friend in friends:
            bullying_messages_count = BullyingMessage.query.filter_by(user_id=friend.id).count()
            friend_data.append({'user': friend, 'bullying_messages_count': bullying_messages_count})

        return render_template('search_friends.html', friend_data=friend_data, search_query=search_query)
    else:
        return render_template('search_friends.html')

@app.route('/view_tweets/<user_id>', methods=['GET'])
@login_required
def view_tweets(user_id):
    user = User.query.get(user_id)
    tweets = list(user.tweets) if user else None
    return render_template('view_tweets.html', user=user, tweets=tweets)

# editprofile route here
@app.route('/editprofile', methods=['GET', 'POST'])
@login_required
def editprofile():
    form = EditProfileForm()
    if form.validate_on_submit():
        # retrieve user from the database
        user = User.query.filter_by(id=current_user.id).first()
        # update user's information
        user.firstname = form.firstname.data
        user.lastname = form.lastname.data
        user.email = form.email.data
        user.gender = form.gender.data
        if 'photo' in request.files:
            photo = request.files['photo']
            filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))# Save the file name in the database or the profile picture field in the user form
        
        # commit changes to the database
        current_user.photo = filename
        db.session.commit()
        
        flash('Your profile has been updated successfully', 'success')
        return redirect(url_for('profile'))

    # pre-populate form fields with current user's information
    form.firstname.data = current_user.firstname
    form.lastname.data = current_user.lastname
    form.email.data = current_user.email
    form.gender.data = current_user.gender    
    return render_template('editprofile.html', form=form)


def check_bullying_messages(user):
    bullying_messages_count = BullyingMessage.query.filter_by(user_id=user.id).count()
    if bullying_messages_count > 4:
        user.is_blocked = True
        db.session.commit()
        flash('Your account has been blocked due to multiple bullying messages.', 'danger')
        logout_user()
        
# Navie-Bayes Model
@app.route('/predict', methods=['POST'])
def predict():
    import pandas as pd
    import numpy as np
    import re
    from sklearn.model_selection import train_test_split
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.feature_extraction.text import CountVectorizer
    import joblib

    # Step 1: Load the dataset from CSV file
    data = pd.read_csv('train.csv')

    # Step 2: Check for labels indicating whether comments are bullying or not
    if 'label' not in data.columns:
        raise ValueError('No label found in the dataset')

    # Step 3: Clean and preprocess the text data
    def clean_text(text):
        # Convert to lowercase
        text = text.lower()
        # Remove non-alphanumeric characters
        text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
        # Remove extra whitespaces
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    data['text'] = data['text'].apply(clean_text)

    # Step 4: Balance the dataset by undersampling non-bullying comments
    bullying_data = data[data['label'] == 1]
    non_bullying_data = data[data['label'] == 0].sample(n=len(bullying_data), random_state=42)
    data_balanced = pd.concat([bullying_data, non_bullying_data], axis=0).reset_index(drop=True)

    # Step 5: Define X and y labels for model training
    X = data_balanced['text'].values
    y = data_balanced['label'].values

    # Extract Feature With CountVectorizer
    corpus = X
    cv = CountVectorizer()
    X = cv.fit_transform(corpus)  # Fit the Data

    # Train a Naive Bayes Classifier
    clf = MultinomialNB()
    clf.fit(X, y)

    # Save the classifier to disk
    joblib.dump(clf, 'naivebayes_bullying_model.pkl')

    # Get the comment from the web form
    comment = request.form['comment']
    # Preprocess the comment
    comment_cleaned = clean_text(comment)
    # Vectorize the comment
    comment_vect = cv.transform([comment_cleaned]).toarray()
    # Load the saved classifier from disk
    clf_loaded = joblib.load('naivebayes_bullying_model.pkl')
    # Predict whether the comment is bullying or not
    prediction = clf_loaded.predict(comment_vect)[0]
    user_id = request.form['user_id']

    # Retrieve the user object from the database based on the user_id
    user = User.query.get(user_id)
    text = comment

    # Check if the comment is classified as bullying
    if prediction == 1:
        # Create a new BullyingMessage object with a valid user ID
        bullying_message = BullyingMessage(text=text, user_id=user_id)

        # Add the bullying message to the bullying_messages list of the user
        user.bullying_messages.append(bullying_message)
        db.session.add(bullying_message)
    else:
        # Create a new Tweet object with a valid user ID
        tweet = Tweet(text=text, prediction=prediction, timestamp=datetime.utcnow(), user_id=user_id)

        # Add the tweet to the tweets list of the user
        user.tweets.append(tweet)
        db.session.add(tweet)

    db.session.commit()
    check_bullying_messages(user)

    # Flash message based on the prediction result
    if prediction == 1:
        flash('This comment is classified as bullying!!!', 'error')
    else:
        flash('This comment is classified as not bullying.', 'success')
        flash('Your tweet has been posted!', 'success')
    return redirect(url_for('homepage'))


@app.route('/report_tweet', methods=['POST'])
def report_tweet():
    tweet_id = request.form.get('tweet_id')
    report_reason = request.form.get('report_reason')
    report = Report(tweet_id=tweet_id, reason=report_reason)
    user = User.query.get(current_user.id)
    report.user = user  #  user_id

    db.session.add(report)
    db.session.commit()

    flash('The tweet has been reported successfully!', 'success')
    return redirect(url_for('homepage'))



@app.route('/block_user', methods=['POST'])
def block_user():
    # Check if the user requesting the block is the admin
    if not current_user.is_authenticated or not current_user.is_admin:
        return redirect(url_for('login'))
    
    # Get the username of the user to be blocked from the web form
    username = request.form.get('username')

    # Update the user's status in the database to enable blocking
    user = User.query.filter_by(username=username).first()
    user.is_blocked = True
    db.session.commit()

    
    flash('The user has been successfully Blcoked')
    return redirect(url_for('admin_dashboard'))


@app.route('/unblock_user', methods=['POST'])
def unblock_user():
    # Check if the user requesting the block is the admin
    if not current_user.is_authenticated or not current_user.is_admin:
        return redirect(url_for('login'))

    # Get the username of the user to be unblocked from the web form
    username = request.form.get('username')

    # Update the user's status in the database to enable unblocking
    user = User.query.filter_by(username=username).first()
    user.is_blocked = False
    db.session.commit()
    flash('The user has been successfully unblocked')
    return redirect(url_for('admin_dashboard'))


app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    tweet = Tweet.query.get_or_404(id)
    if tweet.user_id == current_user.id:
        db.session.delete(tweet)
        db.session.commit()
        flash('Tweet deleted successfully!', 'success')


    return redirect(url_for('homepage', username=current_user.username))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('homepage'))        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

        if user.is_blocked:
            flash('Your account has been blocked.')
            return redirect(url_for('logout'))
        
        login_user(user, remember=remember)

        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('homepage'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        current_user.is_blocked = False
        db.session.commit()

    logout_user()
    return redirect(url_for('login'))


# Admin Dashboard View
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('homepage'))
    users = User.query.all()
    reports = Report.query.all() # Set the variable 'reports' for querying the reports
    return render_template('admin_dashboard.html', users=users, predict=predict, reports=reports)


@app.route('/support')
def support():
    return render_template('support.html')


@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run()
