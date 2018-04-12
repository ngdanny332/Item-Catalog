# Item Catalog Project

Developed a content management system using the Flask framework in Python. Authentication is provided via OAuth and all data is stored within a PostgreSQL database. Authenticated users will have the ability to post, edit, and delete their own items.

## Tools and Frameworks
This web application was built with HTML5, CSS, Bootstrap, Vagrant, Flask, SQLAlchemy, Google Oauth2 & APIs.
## Instruction
To run the web application:
1. Install Vagrant and Virtual Box
2. Launch the Vagrant VM (by typing `vagrant up` in the directory, followed by `winpty vagrant ssh`, */vagrant* from the terminal).
3. From directory */vagrant*, initialize the application database by typing `python database_setup.py` follows by `python database_info.py`.
4. From directory */vagrant*, run the application within the VM by typing `python catalog.py` into the Terminal.
5. Access the application by visiting http://localhost:5000 locally on the browser.
