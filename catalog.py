from flask import (Flask,
                   render_template,
                   request,
                   redirect,
                   jsonify,
                   url_for,
                   flash)
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Sport, Equipment, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Sports Catalog Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///sportscatalogwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    Gathers data from Google Sign In API and
    places it inside a session variable.
    """
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
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
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('User is already connected.'), 200)
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
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += """' " style = "width: 300px; height: 300px;border-radius: 150px;
    -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '"""
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).first()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    """Only disconnect a connected user."""
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to disconnect.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Jsonify API endpoint for sports
@app.route('/sports/<int:sport_id>/equipment/JSON')
def sportEquipmentJSON(sport_id):
    """ JSON API endpoints """
    sport = session.query(Sport).filter_by(id=sport_id).one()
    equipment = session.query(Equipment).filter_by(sport_id=sport_id).all()
    return jsonify(Equipment=[i.serialize for i in equipment])


# Jsonify API endpoint for sport equipments
@app.route('/sports/<int:sport_id>/equipment/<int:equipment_id>/JSON')
def equipmentJSON(sport_id, equipment_id):
    equipment = session.query(Equipment).filter_by(id=equipment_id).one()
    return jsonify(equipment=equipment.serialize)


# Jsonify API endpoint for homepage
@app.route('/sports/JSON')
def sportsJSON():
    sports = session.query(Sport).all()
    return jsonify(sports=[s.serialize for s in sports])


# Show all sports
@app.route('/')
@app.route('/sports/')
def showSports():
    sports = session.query(Sport).order_by(asc(Sport.name))
    if 'username' not in login_session:
        return render_template('publicSports.html', sports=sports)
    else:
        return render_template('Sport.html', sports=sports)


# Add a new sport
@app.route('/sports/new', methods=['GET', 'POST'])
def newSport():
    if 'username' not in login_session:
        return redirect('/login)')
    if request.method == 'POST':
        newSport = Sport(name=request.form['name'],
                         user_id=login_session['user_id'])
        session.add(newSport)
        flash('New Sport "%s" Successfully Created' % newSport.name)
        session.commit()
        return redirect(url_for('showSports'))
    else:
        return render_template('newSport.html')


# Edit a sport
@app.route('/sports/<int:sport_id>/edit/', methods=['GET', 'POST'])
def editSport(sport_id):
    editedSport = session.query(Sport).filter_by(id=sport_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedSport.user_id != login_session['user_id']:
        return """<script>function myFunction() {alert('You are not authorized
                to edit this sport.');}</script><body onload='myFunction()'>"""
    if request.method == 'POST':
        if request.form['name']:
            editedSport.name = request.form['name']
            flash('Sport Successfully Edited %s' % editedSport.name)
            return redirect(url_for('showSports'))
    else:
        return render_template('editSport.html', sport=editedSport)


# Delete a sport
@app.route('/sports/<int:sport_id>/delete/', methods=['GET', 'POST'])
def deleteSport(sport_id):
    if 'username' not in login_session:
        return redirect('/login')
    sportToDelete = session.query(
        Sport).filter_by(id=sport_id).one()
    if sportToDelete.user_id != login_session['user_id']:
        return """<script>function myFunction() {alert('You are not authorized
                to delete this sport. Please create your own sport in order to
                 delete.');}</script><body onload='myFunction()'>"""
    if request.method == 'POST':
        session.delete(sportToDelete)
        flash('%s Successfully Deleted' % sportToDelete.name)
        session.commit()
        return redirect(url_for('showSports', sport_id=sport_id))
    else:
        return render_template('deleteSport.html', sport=sportToDelete)


# Show equipment catalog
@app.route('/sports/<int:sport_id>/')
@app.route('/sports/<int:sport_id>/equipment')
def sportCatalog(sport_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    creator = getUserInfo(sport.user_id)
    equipment = session.query(Equipment).filter_by(
        sport_id=sport_id).all()
    if 'username' not in login_session or \
            creator.id != login_session['user_id']:
        return render_template('publicEquipment.html', equipment=equipment,
                               sport=sport, creator=creator)
    else:
        return render_template('Equipment.html', equipment=equipment,
                               sport=sport, creator=creator)


# Add New Items
@app.route('/sports/<int:sport_id>/equipment/new/', methods=['GET', 'POST'])
def newEquipment(sport_id):
    if 'username' not in login_session:
        return redirect('/login')
    sport = session.query(Sport).filter_by(id=sport_id).one()
    if login_session['user_id'] != sport.user_id:
        return """<script>function myFunction() {alert('You are not authorized
                to add equipment to this sport. Please create your own sport
                 in order to add equipment.
                ');}</script><body onload='myFunction()'>"""
    if request.method == 'POST':
        newItem = Equipment(name=request.form['name'],
                            description=request.form['description'],
                            price=request.form['price'],
                            sport_id=sport_id,
                            user_id=sport.user_id)
        session.add(newItem)
        session.commit()
        flash("New Equipment Added!")
        return redirect(url_for('sportCatalog', sport_id=sport_id))
    else:
        return render_template('newEquipment.html', sport_id=sport_id)


# Edit Item
@app.route('/sports/<int:sport_id>/equipment/<int:equipment_id>/edit/',
           methods=['GET', 'POST'])
def editEquipment(sport_id, equipment_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Equipment).filter_by(id=equipment_id).one()
    sport = session.query(Sport).filter_by(id=sport_id).one()
    if login_session['user_id'] != sport.user_id:
        return """<script>function myFunction() {alert('You are not authorized
                to edit equipment to this sport. Please create your own sport
                 in order to edit equipment.
                ');}</script><body onload='myFunction()'>"""
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        session.add(editedItem)
        session.commit()
        flash("Equipment Updated!")
        return redirect(url_for('sportCatalog', sport_id=sport_id))
    else:
        return render_template('editEquipment.html', sport_id=sport_id,
                               equipment_id=equipment_id, item=editedItem)


# Delete Equipment
@app.route('/sports/<int:sport_id>/equipment/<int:equipment_id>/delete/',
           methods=['GET', 'POST'])
def deleteEquipment(sport_id, equipment_id):
    if 'username' not in login_session:
        return redirect('/login')
    sport = session.query(Sport).filter_by(id=sport_id).one()
    itemToDelete = session.query(Equipment).filter_by(id=equipment_id).one()
    if login_session['user_id'] != sport.user_id:
        return """<script>function myFunction() {alert('You are not authorized
                to delete equipment to this sport. Please create your own sport
                 in order to delete equipment.
                ');}</script><body onload='myFunction()'>"""

    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Equipment deleted!")
        return redirect(url_for('sportCatalog', sport_id=sport_id))
    else:
        return render_template('deleteEquipment.html', item=itemToDelete)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        flash("You have successfully been logged out.")
        return redirect(url_for('showSports'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showSports'))

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
