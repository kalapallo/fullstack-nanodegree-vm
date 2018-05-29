# FSND - Catalog

This program starts a Python web server that connects to a "catalog" database to fetch and display its contents. The catalog contains data on categories and items, and also the users using the application. The front end of the application allows the user to view the contents of the catalog freely, and after authenticating users via Google OAuth, the user can also add, modify and remote items and categories.

## Running the application

Before running the application, the user must register the app on Google and get a valid client ID and a client secret. These are required so that the authentication can work.

To run the application, open a terminal in the main directory and run "python application.py" without the quote marks. This will start the web application on localhost in port 8000. The app can be accessed at http://localhost:8000. On first run, the application doesn't show any data because the database is empty. To populate the database, the user must log in using his or her Google account by clicking on the Login button. After logging in, an "Add item" link appears.

## Limitations

* Login data does not persist between sessions. If the application is restarted, the user must login again.
* A Google account is needed for logging in and authenticating users.

## Programs and packages required

Python 2.7, Flask, SQLAlchemy, Requests, httplib2, oauth2client, flask_httpauth
