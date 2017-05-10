from flask                          import Flask

from natpmp_operation.common_utils  import printlog

import settings


def init_web_interface():

    flask_app = Flask(__name__)

    @flask_app.route("/")
    def hello_world():
        from natpmp_operation import natpmp_logic_common
        return str(natpmp_logic_common.CURRENT_MAPPINGS)

    interface_port = settings.WEB_INTERFACE_PORT

    printlog("Web interface up and running at port %s" % interface_port)
    flask_app.run(port=int(interface_port))
