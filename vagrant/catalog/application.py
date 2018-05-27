from models import Base, User, Category, Item
from flask import Flask, render_template, redirect, url_for
from flask import jsonify, request, make_response, flash
from flask import session as login_session
import random, string
from collections import namedtuple
import requests

from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json

from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


#def login_required(f):
#    @wraps(f)
#    def decorated_function(*args, **kwargs):
#        print "DEBUG: inside login_required() now"
#        if g.user is None:
#            return redirect(url_for('show_login', next=request.url))
#        return f(*args, **kwargs)
#    return decorated_function


@auth.verify_password
def verify_password(username_or_token, password):
    print "DEBUG: at verify_password() now"
    print username_or_token
    print password
    username_or_token = login_session.get('access_token')
    print username_or_token
    user_id = User.verify_auth_token(username_or_token)
    print user_id
    if user_id:
        print "user_id TRUE"
        user = session.query(User).filter_by(id=user_id).one()
    else:
        print "NOT user_id"
        user = session.query(User).filter_by(username=username_or_token).first()
        print user
        if not user or not user.verify_password(password):
            print "returning false"
            return False
    g.user = user
    return True


@app.route('/gconnect', methods=['POST'])
def gconnect():
    print("DEBUG: entering gconnect()")
    print(request.args)
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        print("DEBUG: trying")
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json',
            scope='https://www.googleapis.com/auth/userinfo.profile',
            redirect_uri='postmessage')
            #redirect_uri='http://localhost:8000/')
        ### TEST ###
        #flow = OAuth2WebServerFlow(client_id='your_client_id',
        #                   client_secret='your_client_secret',
        #                   scope='https://www.googleapis.com/auth/calendar',
        #                   redirect_uri='http://example.com/auth_return')
        ### END ###

        #auth_uri = oauth_flow.step1_get_authorize_url()
        #print auth_uri
        #redirect(auth_uri)
        #print "redirect done?"

        #https://accounts.google.com/o/oauth2/auth?
        #    scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile&
        #    redirect_uri=postmessage&
        #    response_type=code&
        #    client_id=899633532195-398cams8rt9av54r67cbna75hga6grrs.apps.googleusercontent.com&
        #    access_type=offline


        # AHAA!


        oauth_flow.redirect_uri = 'postmessage'
        print("DEBUG: " + code)
        credentials = oauth_flow.step2_exchange(code)
        print("DEBUG: trying done")
    except FlowExchangeError as err:
        print("DEBUG: failed")
        print err
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token

    # TODO HANNU: might need to do this instead (from forums):
    #data = request.data.decode('utf8')
    #credentials = json.loads(data)

    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        print "DEBUG: login error"
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        print "DEBUG: Token's user ID doesn't match given user ID."
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "DEBUG: Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        print "DEBUG: user already connected"
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # check if user exists already
    user_id = get_user_ID(login_session['email'])
    print "DEBUG: CHECKING IF USER ALREADY EXISTS"
    print user_id
    if not user_id:
        create_user(login_session)
    login_session['user_id'] = user_id
    #user = session.query(User).filter_By(id = user_id).one()
    #if (user)
    #    print('user already exists')
    #else
    #    print('new user, create it')
    #    createUser(login_session)

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % \
        login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.',
            400))
        response.headers['Content-Type'] = 'application/json'
    return response


def create_user(login_session):
    print "DEBUG: CREATING NEW USER"
    new_user = User(username=login_session['username'],
        email=login_session['email'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def get_user_ID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    print "DEBUG " + state
    return render_template('login.html', STATE=state)


@app.route('/')
def show_catalog():
    categories = session.query(Category).all()

    items = session.query(Item, Category).filter(Category.id == Item.category) \
        .order_by(desc(Item.date_added)).limit(10).all()

    logged_in = 'username' in login_session
    print logged_in

    return render_template("catalog.html", logged_in=logged_in,
        categories=categories, items=items)


@app.route('/catalog/<category>/items')
def show_items(category):
    cat = None
    try:
        cat = session.query(Category).filter_by(name=category).one()
    except:
        return render_template("error.html", error="Category not found")

    items = session.query(Item, Category).filter(
        Item.category == cat.id).filter(Category.id == Item.category).all()

    return render_template("items.html", category=cat.name, items=items)


@app.route('/catalog/<category>/<item_id>')
def show_item(category, item_id):
    try:
        item_object = session.query(Item, Category).filter(
            Category.name == category).filter(Item.id == item_id).one()

        logged_in = 'username' in login_session

        return render_template("item.html", logged_in=logged_in,
            item=item_object.Item, category=item_object.Category)
    except:
        error = "Item or category not found"
        return render_template("error.html", error=error)


@app.route('/catalog/add', methods=['GET', 'POST'])
@auth.login_required
def add_item():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        new_category = request.form['new_category']

        category_id = ''
        if category == 'new_category_option':
            print "creating new category"
            # Create new category item
            category = new_category
            c = Category(name=category)
            session.add(c)
            session.commit()

            item_category = session.query(Category).filter_by(name=category).one()
            category_id = item_category.id
            category = item_category.name
        else:
            print "existing category, category id = " + category
            old_category = session.query(Category).filter_by(id=category).one()
            category_id = old_category.id
            category = old_category.name

        item = Item()
        item.name = name
        item.description = description
        item.category = category_id

        session.add(item)
        session.commit()

        print "added item"

        return redirect(url_for('show_items', category=category))
    else:
        categories = session.query(Category).all()
        print categories
        return render_template("add_item.html", categories=categories)


@app.route('/catalog/<item_id>/edit', methods=['GET', 'POST'])
@auth.login_required
def edit_item(item_id):

    # TODO: combine functionality with add_item

    item = None
    try:
        item = session.query(Item).filter_by(id=item_id).one()
    except:
        return render_template("error.html", "Item does not exist")

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        new_category = request.form['new_category']

        category_id = ''
        # Create new category for item
        if category == 'new_category_option':
            c = Category(name=new_category)
            session.add(c)
            category_id = c.id
        else:
            category_id = category

        # Update item
        item.name = name
        item.description = description
        item.category = category_id

        session.add(item)
        session.commit()

        cat = session.query(Category).filter_by(id=category_id).one()

        return redirect(url_for('show_items', category=cat.name))
    else:
        categories = session.query(Category).all()
        item = session.query(Item).filter_by(id=item_id).one()

        return render_template("edit_item.html", categories=categories,
            item=item)


@app.route('/catalog/<item_id>/delete', methods=['GET', 'POST'])
@auth.login_required
def delete_item(item_id):
    item = None
    try:
        item = session.query(Item).filter_by(id=item_id).one()
    except:
        return render_template("error.html", "Item does not exist")

    if request.method == 'POST':
        category = session.query(Category).filter_by(id=item.category).one()

        session.delete(item)
        session.commit()

        print "deleted item!"
        return redirect(url_for('show_items', category=category.name))
    else:
        return render_template("delete_item.html", item=item)


@app.route('/catalog.json')
def show_json():
    categories = session.query(Category).all()
    return jsonify(Category=[i.serialize for i in categories])


if __name__ == '__main__':
    app.secret_key = 'my_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
