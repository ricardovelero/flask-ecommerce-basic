from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
import requests
from dotenv import load_dotenv
import os
load_dotenv()
dato_cms_key = os.getenv("DATOCMS_READ_API_KEY")

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session management

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Dummy user data for demonstration purposes
users = [
    {'id': '1', 'username': 'user1',
        'password': generate_password_hash('password1')},
    {'id': '2', 'username': 'user2',
        'password': generate_password_hash('password2')}
]


# User model
class User(UserMixin):
    pass


# User loader function required by Flask-Login
@login_manager.user_loader
def load_user(user_id):
    user = User()
    user.id = user_id
    return user


# GraphQL API endpoint
GRAPHQL_API_URL = 'https://graphql.datocms.com/'


def fetch_products():
    # GraphQL query to fetch products
    query = """
      query MyQuery {
        allProductos {
          id
          name
          price
        }
      }
    """

    headers = {
        'Authorization': 'Bearer ' + dato_cms_key
    }

    # Send a POST request to the GraphQL API with the query
    response = requests.post(GRAPHQL_API_URL, json={
                             'query': query}, headers=headers)
    data = response.json()

    # Extract the products from the response data
    products = data['data']['allProductos']

    return products


# Set up Stripe API keys
stripe.api_key = 'your_stripe_secret_key'


def find_item_by_id(item_list, target_id):
    for item in item_list:
        if item['id'] == target_id:
            return item
    return None


@app.route('/')
def home():
    products = fetch_products()  # Fetch products from the GraphQL API
    return render_template('index.html', products=products)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username is already taken
        if any(user['username'] == username for user in users):
            return 'Username is already taken.'

        # Create a new user object
        user = User()
        user.id = str(len(users) + 1)  # Assign a unique ID
        user.username = username
        user.password = generate_password_hash(password)

        # Add the user to the list of users
        users.append(user.__dict__)

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find the user with the provided username
        user = next(
            (user for user in users if user['username'] == username), None)

        # Check if the user exists and the password is correct
        if user and check_password_hash(user['password'], password):
            user_obj = User()
            user_obj.id = user['id']

            # Login the user
            login_user(user_obj)

            return redirect(url_for('dashboard'))
        else:
            return 'Invalid username or password.'

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    # Logout the user
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    product_id = request.form['product_id']  # Get the product ID from the form
    quantity = int(request.form['quantity'])  # Get the quantity from the form

    # Initialize the cart in session if it doesn't exist
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Update the cart with the selected product and quantity
    if product_id in cart:
        cart[product_id] += quantity
    else:
        cart[product_id] = quantity

    session['cart'] = cart
    session['message'] = 'Product added to cart successfully'

    return redirect(url_for('cart'))


@app.route('/cart')
def cart():
    cart = session.get('cart', {})  # Get the cart from the session
    # Get the message from the session
    message = session.pop('message', None)

    # Fetch product information based on the product IDs in the cart
    products = fetch_products()  # Fetch products from the GraphQL API

    cart_items = []
    total_price = 0

    # Calculate the total price and construct the cart item list
    for product_id, quantity in cart.items():
        product = find_item_by_id(products, product_id)
        if product:
            item_total = quantity * product['price']
            total_price += item_total
            cart_items.append(
                {'product': product, 'quantity': quantity, 'item_total': item_total})

    return render_template('cart.html', cart_items=cart_items, total_price=total_price, message=message)


@app.route('/update_quantity', methods=['POST'])
def update_quantity():
    cart = session.get('cart', {})  # Get the cart from the session
    product_id = request.form['product_id']
    quantity = int(request.form['quantity'])

    # Update the quantity of the specified product in the cart
    for item in cart.items():
        if item[0] == product_id:
            cart[product_id] = quantity
            session['cart'] = cart
            break

    # Store a message in the session to display on the cart page
    session['message'] = 'Quantity updated successfully'

    return redirect(url_for('cart'))


@app.route('/remove_item', methods=['POST'])
def remove_item():
    cart = session.get('cart', {})  # Get the cart from the session
    product_id = request.form['product_id']

    # Update the quantity of the specified product in the cart
    for item in cart.items():
        if item[0] == product_id:
            del cart[product_id]
            session['cart'] = cart
            break

    # Store a message in the session to display on the cart page
    session['message'] = 'Item removed successfully'

    return redirect(url_for('cart'))


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        # Retrieve the necessary information from the checkout form
        name = request.form['name']
        email = request.form['email']
        address = request.form['address']
        city = request.form['city']
        postal_code = request.form['postal_code']
        # ... Retrieve other required information

        # Retrieve the cart from the session
        cart = session.get('cart', {})

        # Fetch product information based on the product IDs in the cart
        products = {
            'product1': {'name': 'Product 1', 'price': 10},
            'product2': {'name': 'Product 2', 'price': 20},
            'product3': {'name': 'Product 3', 'price': 15},
        }

        line_items = []

        # Construct the line items for the Stripe checkout
        for product_id, quantity in cart.items():
            product = products.get(product_id)
            if product:
                line_item = {
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': product['name'],
                        },
                        # Amount in cents
                        'unit_amount': int(product['price'] * 100),
                    },
                    'quantity': quantity,
                }
                line_items.append(line_item)

        # Create a Stripe checkout session
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=line_items,
            mode='payment',
            success_url='http://your-website.com/success',  # Specify your success URL
            cancel_url='http://your-website.com/cancel',  # Specify your cancel URL
        )

        # Render the checkout page with the Stripe checkout session ID
        return render_template('checkout.html', session_id=session.id)

    # Render the checkout page
    return render_template('checkout.html')


if __name__ == '__main__':
    app.run(debug=True)
