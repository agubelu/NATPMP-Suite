from flask                          import Flask, session, request, render_template, redirect
from natpmp_operation.common_utils  import printlog, is_valid_ip_string

import settings
import os


def init_web_interface():

    # TODO edicion de lifetime
    flask_app = Flask(__name__, static_folder="webapp/static", template_folder="webapp/templates")
    flask_app.secret_key = os.urandom(16)
    interface_port = settings.WEB_INTERFACE_PORT

    # Supress flask logging unless debug mode is on
    if not settings.DEBUG:
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

    # Create the routers

    @flask_app.route("/", methods=["GET", "POST"])
    def index_handler():
        if request.method == "GET":
            # GET request, display the password input form if there's a password set
            if settings.WEB_INTERFACE_PASSWORD:
                return render_template("index.html", message=None)
            else:
                return redirect("/dashboard")
        else:
            # POST request
            if "password" in request.form and request.form["password"] == settings.WEB_INTERFACE_PASSWORD:
                session["allowed"] = True
                return redirect("/dashboard")
            else:
                return render_template("index.html", message="The password is not correct.")

    @flask_app.route("/dashboard", methods=["GET"])
    def dashboard_handler():
        # Ensure that the user has introduced the correct pasword
        if settings.WEB_INTERFACE_PASSWORD and not session.get("allowed", False):
            return redirect("/")

        from natpmp_operation import natpmp_logic_common
        mappings = natpmp_logic_common.get_mappings_dicts()

        # Send the datetime objects for the lifetime of every mapping
        # (not included by default since it's implicit in the job)
        for mapping in mappings:
            mapping['expiration_date'] = str(mapping['job'].next_run_time)[:19]

        return render_template("dashboard.html", mappings=mappings)

    @flask_app.route("/delete-mapping", methods=["GET"])
    def delete_mapping_handler():
        # Ensure that the user has introduced the correct pasword
        if settings.WEB_INTERFACE_PASSWORD and not session.get("allowed", False):
            return redirect("/")

        ip = request.args.get('ip', None)
        port = int(request.args.get('port', None))
        proto = request.args.get('proto', None)

        # If it exists, remove it
        from natpmp_operation import natpmp_logic_common
        mappings = natpmp_logic_common.CURRENT_MAPPINGS

        if ip in mappings and port in mappings[ip] and proto in mappings[ip][port]:
            natpmp_logic_common.remove_mapping(ip, port, proto, "Deleted via web interface")

        return redirect("/dashboard")

    @flask_app.route("/create-mapping", methods=["GET", "POST"])
    def create_mapping_handler():
        # Ensure that the user has introduced the correct pasword
        if settings.WEB_INTERFACE_PASSWORD and not session.get("allowed", False):
            return redirect("/")

        # Auxiliary function
        def mapping_view(message, form):
            return render_template("create-mapping.html", public_ips=settings.PUBLIC_INTERFACES, message=message, form=form)

        if request.method == "GET":
            return mapping_view(None, {'public_ip': '', 'public_port': 1, 'private_ip': '', 'private_port': 1, 'proto': '', 'lifetime': 3600})
        else:
            # Check that all params are there
            if not all(k in request.form for k in ['public_ip', 'public_port', 'private_ip', 'private_port', 'proto', 'lifetime']):
                return mapping_view("At least one mandatory field wasn't provided.", request.form)

            # Check that they are all OK
            public_ip = request.form['public_ip']
            if not is_valid_ip_string(public_ip) or public_ip not in settings.PUBLIC_INTERFACES:
                return mapping_view("The public interface is not valid.", request.form)

            public_port = request.form['public_port']
            try:
                public_port = int(public_port)
                if not 1 <= public_port <= 65535:
                    raise ValueError
            except ValueError:
                return mapping_view("The public port must be between 1 and 65535.", request.form)

            if public_port in settings.EXCLUDED_PORTS or not settings.MIN_ALLOWED_MAPPABLE_PORT <= public_port <= settings.MAX_ALLOWED_MAPPABLE_PORT:
                return mapping_view("That public port is excluded per configuration settings, please select another one.", request.form)

            private_ip = request.form['private_ip']
            if not is_valid_ip_string(private_ip):
                return mapping_view("The client address is not valid.", request.form)

            private_port = request.form['private_port']
            try:
                private_port = int(private_port)
                if not 1 <= private_port <= 65535:
                    raise ValueError
            except ValueError:
                return mapping_view("The private port must be between 1 and 65535.", request.form)

            proto = request.form['proto']
            if proto not in ["TCP", "UDP"]:
                return mapping_view("The protocol is not recognized", request.form)

            lifetime = request.form['lifetime']
            try:
                lifetime = int(lifetime)
                if not 1 <= lifetime <= 65535:
                    raise ValueError
            except ValueError:
                return mapping_view("The lifetime must be between 1 and 65535.", request.form)

            from natpmp_operation import natpmp_logic_common
            lifetime = natpmp_logic_common.get_acceptable_lifetime(lifetime)

            # Parameters are correct, check that the mapping can actually be made

            # Check that the client doesn't have another mapping for that public IP and private port
            cur_mappings = natpmp_logic_common.get_mappings_client([public_ip], [private_port], [proto], private_ip)
            if cur_mappings and cur_mappings[0]['public_port'] != public_port:
                return mapping_view("That client already has another mapping for the desired private port, public IP and protocol.", request.form)
            elif cur_mappings and cur_mappings[0]['public_port'] == public_port:
                # The client already has this mapping, refresh it
                natpmp_logic_common.create_mapping(public_ip, public_port, proto, private_ip, private_port, lifetime)
                return redirect("/dashboard")

            # Check that the mapping can be made and do it if so
            if natpmp_logic_common.is_new_mapping_available(public_ip, public_port, proto, private_ip):
                natpmp_logic_common.create_mapping(public_ip, public_port, proto, private_ip, private_port, lifetime)
                return redirect("/dashboard")
            else:
                return mapping_view("That mapping cannot be created because it's already asigned to another client.", request.form)

    #########################################################################################################

    # Run the app
    printlog("Web interface up and running at port %s" % interface_port)
    flask_app.run(port=int(interface_port))
