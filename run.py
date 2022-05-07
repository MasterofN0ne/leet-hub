from files import app
from files import db
from files import models


if __name__ == "__main__":
    app.run(debug=True,host='127.0.0.1', port=5003)