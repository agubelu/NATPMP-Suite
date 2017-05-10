from flask                          import Flask, session, request, render_template

from natpmp_operation.common_utils  import printlog

import settings
import os


def init_web_interface():

    # TODO quitar el logging de flask
    # TODO hacer from natpmp_operation import natpmp_logic_common dentro del metodo
    flask_app = Flask(__name__, static_folder="webapp/static", template_folder="webapp/templates")
    flask_app.secret_key = os.urandom(16)
    interface_port = settings.WEB_INTERFACE_PORT

    # Create the routers

    @flask_app.route("/", methods=["GET", "POST"])
    def hello_world():
        if request.method == "GET":
            return render_template("index.html", message=None)

    # Run the app
    printlog("Web interface up and running at port %s" % interface_port)
    flask_app.run(port=int(interface_port))
