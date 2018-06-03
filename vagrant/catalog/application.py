from models import Base, User, Category, Item
from flask import Flask, render_template, redirect, url_for
from flask import jsonify, request, make_response, flash
from flask import session as login_session
from functools import wraps
import random
import string
import requests

from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound

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


def login_required(f):
    """
    login_required: Decorator to check the login status
        Args:
            f (func): Function that is decorated with this
        Returns:
            Parameter function if user is logged in, redirect to
            login page is user is not logged in
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            flash("You are not allowed to access this resource")
            return redirect('/login')
    return decorated_function


@auth.verify_password
def verify_token(username_or_token, password):
    """
    verify_token: Verify the user auth token
        Args:
            username_or_token (str): the token to be verified
            password (str): obsolete parameter
        Returns:
            True if token matches, False otherwise
    """
    # Actually arguments are not used, just check if logged in
    # NOTE: only works within a session, so the user must re-login
    # everytime the app is restarted
    token = login_session.get('auth_token')

    if not token:
        return False

    user_id = User.verify_auth_token(token)
    if user_id:
        # user = session.query(User).filter_by(id=user_id).one()
        return True
    else:
        return False


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    gconnect: Connect to Google server and authenticates user. If user
    does not exist, create a new user.
        Args:
            -
        Returns:
            HTTP response on fail, HTML string on success
    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets(
            'client_secrets.json',
            scope='https://www.googleapis.com/auth/userinfo.profile',
            redirect_uri='postmessage')

        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError as err:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token

    # TODO: might need to do this instead (from forums):
    # data = request.data.decode('utf8')
    # credentials = json.loads(data)

    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'),
            200)
        response.headers['Content-Type'] = 'application/json'
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

    # Check if user exists already
    user_id = get_user_ID(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    user = session.query(User).filter_by(id=user_id).one()
    auth_token = user.generate_auth_token()
    login_session['auth_token'] = auth_token

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: \
        150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    """
    gdisconnect: Disconnect user from Google server and destroy authentication
    credentials.
        Args:
            -
        Returns:
            HTTP response
    """
    access_token = login_session.get('access_token')
    if access_token is None:
        # print 'Access Token is None'
        response = make_response(json.dumps(
            'Current user not connected.'),
            401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # print 'In gdisconnect access token is %s', access_token
    # print 'User name is: '
    # print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % \
        login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    # print 'result is '
    # print result

    # Seems like the disconnect has to be forced because a lot of times the
    # returned code is 400 due to tokens not matching. Which makes it
    # impossible to disconnect a user. Okay.

    #if result['status'] == '200':
    if True:
        del login_session['access_token']
        del login_session['auth_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.',
            400))
        response.headers['Content-Type'] = 'application/json'
    return response


def create_user(login_session):
    """
    create_user: Create a new user in the database
        Args:
            login_session (dict): dictionary of the login session
        Returns:
            Newly created user's ID
    """
    new_user = User(username=login_session['username'],
                    email=login_session['email'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()

    return user.id


def get_user_ID(email):
    """
    get_user_ID: Get the ID of a user based on their email address
        Args:
            email (str): email address of user
        Returns:
            Newly created user's ID
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except NoResultFound as err:
        return None


@app.route('/login')
def show_login():
    """
    show_login: Show the main login page
        Args:
            -
        Returns:
            login.html template
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/logout')
def logout():
    """
    logout: Log the user out
        Args:
            -
        Returns:
            Redirect to routing page or back to home screen
    """
    if 'username' in login_session:
        # Disconnect first
        gdisconnect()

        flash('You were successfully logged out')

        # Redirect in some cases
        sender = request.args.get('sender')  # sender URL
        param1 = request.args.get('param1')  # 1st argument for url_for
        param2 = request.args.get('param2')  # 2nd argument for url_for

        # I was trying to be smart and redirect back to the original page,
        # but didn't find any nice ways to do it so just include the
        # information as parameters... but seems like it doesn't work se well

        if sender and param1 and param2:
            # Only used for 'show_item'
            return redirect(url_for(sender, category=param1, item_id=param2))
            # Looks like this idea didn't work out...
            # So much for a generic solution
            # return redirect(url_for(sender, param1, param2))
        elif sender and param1:
            # Only used for 'show_items'
            return redirect(url_for(sender, category=param1))
            # return redirect(url_for(sender, param1))

        # No redirecting, go back to main page
        return redirect(url_for('show_catalog'))


@app.route('/')
def show_catalog():
    """
    show_catalog: Show the main screen
        Args:
            -
        Returns:
            HTML for the catalog.html page
    """
    categories = session.query(Category).all()

    items = session.query(Item, Category).filter(Category.id == Item.category) \
        .order_by(desc(Item.date_added)).limit(10).all()

    logged_in = 'username' in login_session

    return render_template("catalog.html", logged_in=logged_in,
                           categories=categories, items=items)


@app.route('/catalog/<category>/items')
def show_items(category):
    """
    show_items: Show the items in the given category
        Args:
            category (int): ID of the category to show
        Returns:
            HTML for the error page if category invalid, or
            items.html if category is valid
    """
    cat = None
    try:
        cat = session.query(Category).filter_by(name=category).one()
    except NoResultFound as err:
        return render_template("error.html", error="Category not found")

    items = session.query(Item, Category).filter(
        Item.category == cat.id).filter(Category.id == Item.category).all()

    logged_in = 'username' in login_session

    return render_template("items.html", logged_in=logged_in,
                           category=cat.name, items=items)


@app.route('/catalog/<category>/<item_id>')
def show_item(category, item_id):
    """
    show_item: Show one item in a given category
        Args:
            category (int): ID of the category where the item is
            item_id (int): ID of the item to show
        Returns:
            HTML for the error page if category or item is invalid
            or item does not belong to this category, or
            item.html if category and item are valid
    """
    try:
        item_object = session.query(Item, Category).filter(
            Category.name == category).filter(Item.id == item_id).one()

        logged_in = 'username' in login_session

        return render_template("item.html", logged_in=logged_in,
                               item=item_object.Item,
                               category=item_object.Category)
    except NoResultFound as err:
        error = "Item or category not found"
        return render_template("error.html", error=error)


@app.route('/catalog/add', methods=['GET', 'POST'])
@login_required
def add_item():
    """
    add_item: Add new item to database
        Args:
            -
        Returns:
            If method is POST, redirect back to show_items.html,
            if method is GET, show the add_item.html template
    """
    logged_in = True

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        new_category = request.form['new_category']

        category_id = ''
        if category == 'new_category_option':
            # Create new category item
            category = new_category
            c = Category(name=category)
            session.add(c)
            session.commit()

            item_category = session.query(Category).filter_by(
                name=category).one()
            category_id = item_category.id
            category = item_category.name
        else:
            old_category = session.query(Category).filter_by(
                id=category).one()
            category_id = old_category.id
            category = old_category.name

        item = Item()
        item.name = name
        item.description = description
        item.category = category_id

        # Get the current user
        username = login_session['username']
        user = session.query(User).filter_by(username=username).one()

        item.creator_id = user.id

        session.add(item)
        session.commit()

        return redirect(url_for('show_items', logged_in=logged_in,
                                category=category))
    else:
        categories = session.query(Category).all()
        return render_template("add_item.html", logged_in=logged_in,
                               categories=categories)


@app.route('/catalog/<item_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    """
    edit_item: Edit an item in database
        Args:
            item_id (int): ID of the item to edit
        Returns:
            HTML for the error page if item is invalid,
            redirect back to show_items.html if method is POST,
            show the edit_item.html template if method is GET
    """
    logged_in = True
    item = None
    try:
        item = session.query(Item).filter_by(id=item_id).one()
    except NoResultFound:
        return render_template("error.html", "Item does not exist")

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        new_category = request.form['new_category']

        category_id = ''
        if category == 'new_category_option':
            # Create new category for item
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

        return redirect(url_for('show_items', logged_in=logged_in,
                                category=cat.name))
    else:
        categories = session.query(Category).all()
        item = session.query(Item).filter_by(id=item_id).one()

        if not verify_creator(item.creator_id):
            return redirect(request.referrer)
        # Get the current user ID
        #username = login_session['username']
        #user = session.query(User).filter_by(username=username).one()
        #user_id = user.id

        # If the current user did not create this item,
        # redirect the user back to previous page
        #if user_id != item.creator_id:
        #    flash('You do not have permission to edit this item')
        #    return redirect(request.referrer)

        return render_template("edit_item.html", logged_in=logged_in,
                               categories=categories, item=item)


@app.route('/catalog/<item_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_item(item_id):
    """
    delete_item: Delete an item from database
        Args:
            item_id (int): ID of the item to delete
        Returns:
            HTML for the error page if item is invalid,
            redirect back to show_items.html if method is POST,
            show the delete_item.html template if method is GET
    """
    logged_in = True
    item = None
    try:
        item = session.query(Item).filter_by(id=item_id).one()
    except NoResultFound as err:
        return render_template("error.html", "Item does not exist")

    if request.method == 'POST':
        category = session.query(Category).filter_by(id=item.category).one()

        session.delete(item)
        session.commit()

        return redirect(url_for('show_items', logged_in=logged_in,
                                category=category.name))
    else:
        if not verify_creator(item.creator_id):
            return redirect(request.referrer)

        return render_template("delete_item.html", logged_in=logged_in,
                               item=item)


def verify_creator(creator_id):
    """
    verify_creator: Verify that the current user created an item
        Args:
            creator_id (int): ID of the user that created the given item
        Returns:
            True if current user created the item, False otherwise
    """
    # Get the current user ID
    username = login_session['username']
    user = session.query(User).filter_by(username=username).one()
    user_id = user.id

    # If the current user did not create this item,
    # redirect the user back to previous page
    if user_id != creator_id:
        flash('You do not have permission to edit this item')
        return False

    return True


@app.route('/catalog/<category>/items.json')
@app.route('/catalog/items/<item>.json')
@app.route('/catalog.json')
def show_json(category=None, item=None):
    """
    show_json: Show the JSON endpoint for a given category, item or
    all categories and items
        Args:
            category (int): ID of the category (optional)
            item (int): ID of the item (optional)
        Returns:
            JSON dictionary containing the requested data
    """
    if category is not None:
        try:
            # Try to find category
            cat = session.query(Category).filter_by(id=category).one()
            return jsonify(Category=cat.serialize)
        except NoResultFound as err:
            error = "Category not found"
            return render_template("error.html", error=error)
    elif item is not None:
        try:
            # Try to find item
            itm = session.query(Item).filter_by(id=item).one()
            return jsonify(Item=itm.serialize)
        except NoResultFound as err:
            error = "Item not found"
            return render_template("error.html", error=error)

    # If no category or item has been defined, show all categories and items
    categories = session.query(Category).all()
    return jsonify(Category=[i.serialize for i in categories])


if __name__ == '__main__':
    app.secret_key = 'my_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
