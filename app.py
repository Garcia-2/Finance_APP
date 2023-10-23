import os
import re
import random
import string
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, url_for,request, session
from flask_session import Session
# from flask_mail import Mail, Message
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
#from validate_email_address import validate_email

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")
"""
# Configure Flask-Mail for email sending
#app.config["MAIL_SERVER"] = "smtp.gmail.com"  # Use Gmail SMTP server
#app.config["MAIL_PORT"] = 587  # TLS port
#app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = "my_email"  # Replace with your Gmail email
app.config["MAIL_PASSWORD"] = "my_email_password"  # Replace with your Gmail password
mail = Mail(app)
"""

# Function to generate a random verification token
def generate_verification_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Retrieve user ID from the session
    user_id = session["user_id"]

    # Query the database to get the user's current cash balance
    user_data = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    user_cash = float(user_data[0]["cash"])

    # Query the database to get the user's stock holdings
    stock_holdings = db.execute(
        "SELECT symbol, SUM(shares) as total_shares FROM purchases WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0",
        user_id,
    )

    # Create a list to store information about each stock holding
    stocks_info = []

    # Loop through the user's stock holdings
    for holdings in stock_holdings:
        symbol = holdings["symbol"]
        total_shares = holdings["total_shares"]

        # Use the lookup function to get the current price of the stock
        quote = lookup(symbol)
        if not quote:
            return apology("Unable to retrive stock data", 400)

        stock_price = float(quote["price"])
        total_value = float(total_shares) * float(stock_price)

        stocks_info.append(
            {
                "symbol": symbol,
                "name": quote["name"],
                "shares": total_shares,
                "price": usd(stock_price),
                "total_value": usd(total_value)
            }
        )

    # Calculate the grand total (stocks' total value plus cash)
    grand_total = user_cash + sum(float(info["total_value"].replace(',', '').replace('$', '')) for info in stocks_info)

    return render_template("index.html", stocks_info=stocks_info, user_cash=usd(user_cash), grand_total=usd(grand_total))

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """ Enable Users To Buy shares of stock"""
    if request.method == "POST":

        # Retrieve user input
        symbol = request.form.get("symbol")
        shares_to_buy = request.form.get("shares")

        # Validate user input
        if not symbol:
            return apology("Symbol cannot be empty", 400)

        if not shares_to_buy or not shares_to_buy.isdigit() or float(shares_to_buy) <= 0:
            return apology("Shares must be a positive number", 400)

        # Look up the current price of the stock
        quote = lookup(symbol)

        if not quote:
            return apology("Invalid Symbol", 400)

        # Retrieve the user's current cash balance from the database
        user_id = session["user_id"]

        # Assuming you have a 'users' table in the database with 'id' and 'cash' columns
        result = db.execute("SELECT cash FROM users WHERE id = ?", user_id)

        if result:
            user_cash = result[0]["cash"]

        # Calculate the total cost of the stock purchase
        shares_to_buy = float(shares_to_buy)
        purchase_cost = quote["price"] * shares_to_buy

        # Check if the user has sufficient funds
        if user_cash < purchase_cost:
            return apology("Insufficient Funds", 400)

        # Deduct the purchase cost from the user's cash balance and record the purchase in the database
        user_cash -= purchase_cost
        db.execute("UPDATE users SET cash = ? WHERE id = ?", user_cash, user_id)

        # Insert the purchase record into the 'purchases' table with purchase date and time
        purchase_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.execute("INSERT INTO purchases (user_id, symbol, shares, price, purchase_date) VALUES (?, ?, ?, ?, ?)",
            user_id, symbol, float(shares_to_buy), quote["price"], purchase_datetime)

        # Insert the transaction record into the 'transactions' table with transaction type
        transaction_description = "Stock purchase"
        transaction_type = "BUY"  # Specify the transaction type (e.g., "BUY" for buying stock)
        db.execute("INSERT INTO transactions (user_id, transaction_type, symbol, shares, price, description, amount) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   user_id, transaction_type, symbol, shares_to_buy, quote["price"], transaction_description, purchase_cost)

        # Redirect the user to the home page after a successful purchase
        flash(f"Bought {shares_to_buy} shares of {quote['name']} for {usd(purchase_cost)}")
        return redirect(url_for("index"))
    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Retrieve user ID from the session
    user_id = session["user_id"]

    # Query the database to get all the user's transactions
    transactions = db.execute(
        "SELECT transaction_type, symbol, shares, price, transaction_datetime FROM transactions WHERE user_id = ? ORDER BY transaction_datetime DESC",
        user_id,
    )

    # Render the transactions in an HTML table
    return render_template("history.html", transactions=transactions)
    # return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":

        symbol = request.form.get("symbol")

        quote_data = lookup(symbol)

        if quote_data:

            return render_template("quoted.html", symbol=quote_data["symbol"], price=quote_data["price"])
        else:

            return apology("Symbol not found", 400)
    else:
        return render_template("quote.html")


# Registration route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Retrieve user input
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        #email = request.form.get("email")

        # validate  email
        #if not validate_email(email, verify=True):  # Verify the email format
            #return apology("Invalid email address", 400)

        # Check if the username, password, and email are provided
        if not username:
            return apology("must provide username", 400)

        if not password:
            return apology("must provide password", 400)

        # Check if the password meets the minimum length requirement (e.g., at least 8 characters)
        if len(password) < 8:
            return apology("password must be at least 8 characters", 400)

        # Check if the password meets complexity requirements
        if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$', password):
            return apology("password must contain at least one uppercase letter, one lowercase letter, one symbol, and one number", 400)

        # validate confirmation
        if not confirmation:
            return apology("Must confirm password", 400)

        if confirmation != password:
            return apology("Password confirmation must match password", 400)
        """
        if not email:
            return apology("must provide email", 400)
            """

        # Generate a password hash
        password_hash = generate_password_hash(password)

        # Check if the email is already registered
        """
        existing_user = db.execute("SELECT * FROM users WHERE email = ?", email)
        if existing_user:
            return apology("email is already registered", 400)
            """
        existing_user = db.execute("SELECT * FROM users WHERE username = ?", username)
        if existing_user:
            return apology("username is already registered", 400)

        # Generate a random verification token
        # verification_token = generate_verification_token()

        # Store the verification token and user data in the database
        # I'll have to comment this out for now and use it later just for check50's sake
        """
        db.execute("INSERT INTO users (username, hash, email, verified, verification_token) VALUES (?, ?, ?, 0, ?)",
                    username, password_hash, email, verification_token)
                    """
        # temporary statement, use the one above this one
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                    username, password_hash)

        """
        # Send a verification email to the user
        msg = Message("Confirm Your Email", sender="garcia@moov.life", recipients=[email])
        verification_link = url_for('verify_email', token=verification_token, _external=True)
        msg.body = f"Click the following link to verify your email: {verification_link}"
        mail.send(msg)
        """

        flash("Registration successful!", "success")

        return redirect(url_for("login"))

    else:
        return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        # retrieve user input
        symbol = request.form.get("symbol")
        shares_to_sell = request.form.get("shares")

        # validate user input
        if not symbol:
            return apology("Symbol cannot be empty", 400)

        if not shares_to_sell or not shares_to_sell.isdigit() or float(shares_to_sell) <= 0:
            return apology("Shares must be a positive number", 400)

        # Check if the user owns the selected stock
        user_id = session["user_id"]
        stock_holdings = db.execute("SELECT SUM(shares) as total_shares FROM purchases WHERE user_id = ? AND symbol = ?", user_id, symbol)
        if not stock_holdings or stock_holdings[0]["total_shares"] < float(shares_to_sell):
            return apology("You do not own enough shares of this stock to sell", 400)

        # Use the lookup function to get the current stock price
        quote = lookup(symbol)
        if not quote:
            return apology("Unable to retrieve data", 400)

        # Calculate the total value of the shares to sell
        stock_price = quote["price"]
        total_value = float(shares_to_sell) * stock_price

        # Update the user's cash balance and record the sale in the database
        user_data = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        user_cash = user_data[0]["cash"]
        user_cash += total_value

        # Record the sale in the "transactions" table
        description = f"Sold {shares_to_sell} shares of {symbol}"
        db.execute(
            "INSERT INTO transactions (user_id, transaction_type, symbol, shares, price, description, amount) VALUES (?, ?, ?, ?, ?, ?, ?)",
            user_id, 'SELL', symbol, shares_to_sell, -total_value, description, -total_value,
        )

        # Update the user's cash balance in the "users" table
        db.execute("UPDATE users SET cash = ? WHERE id = ?", user_cash, user_id)

        # Deduct the sold shares from the "purchases" table
        db.execute(
            "INSERT INTO purchases (user_id, symbol, shares, price, purchase_date) VALUES (?, ?, ?, ?, ?)",
            user_id, symbol, -float(shares_to_sell), stock_price, datetime.now()
        )

        # Redirect the user to the home page with a success message
        flash("Stock sold successfully!", "success")
        return redirect("/")

    else:
        # Retrieve the user's stock holdings
        user_id = session["user_id"]
        user_stocks = db.execute("SELECT symbol FROM purchases WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", user_id)

        # Render the "sell.html" template with user_stocks passed as a context variable
        return render_template("sell.html", user_stocks=user_stocks)

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow users to change their password"""
    if request.method == "POST":
        # Retrieve user input
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Retrieve the user's current password hash from the database
        user_id = session["user_id"]
        user_data = db.execute("SELECT hash FROM users WHERE id = ?", user_id)
        current_password_hash = user_data[0]["hash"]

        # Validate user input
        if not current_password or not new_password or not confirm_password:
            return apology("All fields must be filled out", 400)

        if new_password == current_password:
            return apology("New Password Can't Be The Same As the Old Password", 400)

        if not check_password_hash(current_password_hash, current_password):
            return apology("Current password is incorrect", 400)

        if len(new_password) < 8:
            return apology("password must be at least 8 characters", 400)

        # Check if the password meets complexity requirements
        if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$', new_password):
            return apology("password must contain at least one uppercase letter, one lowercase letter, one symbol, and one number", 400)

        if new_password != confirm_password:
            return apology("New passwords do not match", 400)

        # Generate a new password hash and update it in the database
        new_password_hash = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_password_hash, user_id)

        flash("Password changed successfully!", "success")
        return redirect("/")
    else:
        return render_template("change_password.html")

"""

@app.route("/verify_email", methods=["GET"])
def verify_email():
    # Get the verification token from the URL query parameters
    token = request.args.get("token")

    # Query the database to find the user with this token
    user = db.execute("SELECT * FROM users WHERE verification_token = ?", token)

    if not user:
        return render_template("verification_error.html")  # Or any error template you prefer

    # Mark the user's email as verified in the database
    db.execute("UPDATE users SET email_verified = 1 WHERE id = ?", user[0]["id"])

    # Optionally, display a success message
    flash("Email verified successfully!", "success")

    return redirect(url_for("login"))  # Redirect to the login page or any other page you prefer

"""


@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    if request.method == "POST":
        # Retrieve the amount of cash to add from the form
        cash_to_add = float(request.form.get("cash"))

        # Validate the input (e.g., check if the amount is positive)

        # Update the user's cash balance in the database
        user_id = session["user_id"]
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", cash_to_add, user_id)

        # Optionally, record the transaction in the "transactions" table

        # Redirect to a page indicating the cash addition was successful
        flash(f"Added ${cash_to_add:.2f} to your account.", "success")
        return redirect(url_for("index"))
    else:
        return render_template("add_cash.html")