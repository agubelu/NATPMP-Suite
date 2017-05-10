from flask                          import Flask, session, send_from_directory

from natpmp_operation.common_utils  import printlog

import settings
import os


def init_web_interface():

    flask_app = Flask(__name__, static_folder="webapp/static", template_folder="webapp/templates")
    flask_app.secret_key = os.urandom(16)
    interface_port = settings.WEB_INTERFACE_PORT

    # Create the routers

    @flask_app.route("/")
    def hello_world():
        from natpmp_operation import natpmp_logic_common
        return str(natpmp_logic_common.CURRENT_MAPPINGS)

    # Run the app
    printlog("Web interface up and running at port %s" % interface_port)
    flask_app.run(port=int(interface_port))
