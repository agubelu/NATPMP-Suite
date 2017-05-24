from flask                          import Flask, session, request, render_template, redirect, flash
from natpmp_operation.common_utils  import printlog, is_valid_ip_string

import settings
import os


def init_web_interface():

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
            flash("Mapping successfully deleted.", "success")
        else:
            flash("Could not delete mapping.", "danger")

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
                flash("Mapping successfully created.", "success")
                return redirect("/dashboard")

            # Check that the mapping can be made and do it if so
            if natpmp_logic_common.is_new_mapping_available(public_ip, public_port, proto, private_ip):
                natpmp_logic_common.create_mapping(public_ip, public_port, proto, private_ip, private_port, lifetime)
                flash("Mapping successfully created.", "success")
                return redirect("/dashboard")
            else:
                return mapping_view("That mapping cannot be created because it's already asigned to another client.", request.form)

    @flask_app.route("/edit-settings", methods=["GET", "POST"])
    def edit_settings_handler():
        # Ensure that the user has introduced the correct pasword
        if settings.WEB_INTERFACE_PASSWORD and not session.get("allowed", False):
            return redirect("/")

        # Auxiliary function
        def settings_view(message, form):
            return render_template("edit-settings.html", message=message, form=form, pass_enabled=bool(settings.WEB_INTERFACE_PASSWORD))

        if request.method == "GET":
            return settings_view(None, {'allow_v0': settings.ALLOW_VERSION_0, 'allow_v1': settings.ALLOW_VERSION_1, 'allow_tls': settings.ALLOW_SECURITY_IN_V1,
                                        'force_tls': settings.FORCE_SECURITY_IN_V1, 'strict_tls': settings.STRICT_CERTIFICATE_CHECKING,
                                        'max_port': settings.MAX_ALLOWED_MAPPABLE_PORT, 'min_port': settings.MIN_ALLOWED_MAPPABLE_PORT, 'excluded_ports': str(settings.EXCLUDED_PORTS)[1:-1],
                                        'max_lifetime': settings.MAX_ALLOWED_LIFETIME, 'min_lifetime': settings.MIN_ALLOWED_LIFETIME, 'fixed_lifetime': settings.FIXED_LIFETIME,
                                        'blacklist_mode': settings.BLACKLIST_MODE, 'whitelist_mode': settings.WHITELIST_MODE, 'blacklisted_ips': str(settings.BLACKLISTED_IPS)[1:-1].replace("'", "").replace('"', ""),
                                        'whitelisted_ips': str(settings.WHITELISTED_IPS)[1:-1].replace("'", "").replace('"', ""), 'debug': settings.DEBUG})
        else:
            form = request.form
            # Check that the password is there if it's set
            if settings.WEB_INTERFACE_PASSWORD and ("password" not in form or form["password"] != settings.WEB_INTERFACE_PASSWORD):
                return settings_view("The password is not correct.", form)

            # Check that all of the required params are there
            if not all(param in form for param in ["max_port", "min_port", "excluded_ports", "max_lifetime", "min_lifetime", "fixed_lifetime", "blacklisted_ips", "whitelisted_ips"]):
                return settings_view("At least one mandatory field wasn't provided.", form)

            # Dump them into variables
            allow_v0 = "allow_v0" in form and form["allow_v0"]
            allow_v1 = "allow_v1" in form and form["allow_v1"]
            allow_tls = "allow_tls" in form and form["allow_tls"]
            force_tls = "force_tls" in form and form["force_tls"]
            strict_tls = "strict_tls" in form and form["strict_tls"]
            max_port = form["max_port"]
            min_port = form["min_port"]
            excluded_ports = form["excluded_ports"]
            max_lifetime = form["max_lifetime"]
            min_lifetime = form["min_lifetime"]
            fixed_lifetime = form["fixed_lifetime"]
            blacklist_mode = "blacklist_mode" in form and form["blacklist_mode"]
            whitelist_mode = "whitelist_mode" in form and form["whitelist_mode"]
            blacklisted_ips = form["blacklisted_ips"]
            whitelisted_ips = form["whitelisted_ips"]
            debug = "debug" in form and form["debug"]

            # Check that they are all OK
            if not allow_v0 and not allow_v1:
                return settings_view("At least either version must be enabled", form)

            if allow_tls and not allow_v1:
                return settings_view("TLS can only be enabled if v1 is enabled.", form)

            if (force_tls or strict_tls) and not allow_tls:
                return settings_view("TLS settings require that TLS is enabled.", form)

            try:
                max_port = int(max_port)
                if not 1 <= max_port <= 65535:
                    raise ValueError
            except ValueError:
                return settings_view("The maximum port must be between 1 and 65535.", form)

            try:
                min_port = int(min_port)
                if not 1 <= min_port <= 65535:
                    raise ValueError
            except ValueError:
                return settings_view("The minimum port must be between 1 and 65535.", form)

            if not excluded_ports:
                excluded_ports = []
            else:
                tmp = []
                for spl in excluded_ports.split(","):
                    spl = spl.strip()
                    try:
                        spl = int(spl)
                        if not 1 <= spl <= 65535:
                            raise ValueError
                        tmp.append(spl)
                    except ValueError:
                        return settings_view("Port %s from excluded ports is not a valid port." % spl, form)
                excluded_ports = tmp

            try:
                max_lifetime = int(max_lifetime)
                if not max_lifetime >= 1:
                    raise ValueError
            except ValueError:
                return settings_view("The maximum lifetime must be greater than 1.", form)

            try:
                min_lifetime = int(min_lifetime)
                if not min_lifetime >= 1:
                    raise ValueError
            except ValueError:
                return settings_view("The maximum lifetime must be greater than 1.", form)

            if fixed_lifetime:
                try:
                    fixed_lifetime = int(fixed_lifetime)
                    if not fixed_lifetime >= 1:
                        raise ValueError
                except ValueError:
                    return settings_view("The fixed lifetime must be greater than 1.", form)
            else:
                fixed_lifetime = None

            if blacklist_mode and whitelist_mode:
                return settings_view("Blacklist and whitelist mode cannot be both active at once.", form)

            if not blacklisted_ips:
                blacklisted_ips = []
            else:
                tmp = []
                for spl in blacklisted_ips.split(","):
                    spl = spl.strip()
                    if not is_valid_ip_string(spl):
                        return settings_view("IP %s from the blacklist is not a valid address." % spl, form)
                    tmp.append(spl)
                blacklisted_ips = tmp

            if not whitelisted_ips:
                whitelisted_ips = []
            else:
                tmp = []
                for spl in whitelisted_ips.split(","):
                    spl = spl.strip()
                    if not is_valid_ip_string(spl):
                        return settings_view("IP %s from the whitelist is not a valid address." % spl, form)
                    tmp.append(spl)
                    whitelisted_ips = tmp

            # All settings are valid by now, dump them into the settings module
            settings.ALLOW_VERSION_0 = allow_v0
            settings.ALLOW_VERSION_1 = allow_v1
            settings.ALLOW_SECURITY_IN_V1 = allow_tls
            settings.FORCE_SECURITY_IN_V1 = force_tls
            settings.STRICT_CERTIFICATE_CHECKING = strict_tls
            settings.MAX_ALLOWED_MAPPABLE_PORT = max_port
            settings.MIN_ALLOWED_MAPPABLE_PORT = min_port
            settings.EXCLUDED_PORTS = excluded_ports
            settings.MAX_ALLOWED_LIFETIME = max_lifetime
            settings.MIN_ALLOWED_LIFETIME = min_lifetime
            settings.FIXED_LIFETIME = fixed_lifetime
            settings.BLACKLIST_MODE = blacklist_mode
            settings.BLACKLISTED_IPS = blacklisted_ips
            settings.WHITELIST_MODE = whitelist_mode
            settings.WHITELISTED_IPS = whitelisted_ips
            settings.DEBUG = debug

            # Perform some additional changes if needed
            from natpmp_operation import natpmp_logic_common
            if allow_tls and natpmp_logic_common.NATPMP_OPCODE_SENDCERT not in natpmp_logic_common.SUPPORTED_OPCODES[1]:
                natpmp_logic_common.SUPPORTED_OPCODES[1].append(natpmp_logic_common.NATPMP_OPCODE_SENDCERT)
            elif not allow_tls and natpmp_logic_common.NATPMP_OPCODE_SENDCERT in natpmp_logic_common.SUPPORTED_OPCODES[1]:
                natpmp_logic_common.SUPPORTED_OPCODES[1].remove(natpmp_logic_common.NATPMP_OPCODE_SENDCERT)

            import logging
            log = logging.getLogger('werkzeug')

            if debug:
                log.setLevel(logging.DEBUG)
            else:
                log.setLevel(logging.ERROR)

            printlog("Settings changed via web interface.")
            flash("Settings updated.", "success")
            return redirect("/dashboard")

    #########################################################################################################

    # Run the app
    printlog("Web interface up and running at port %s" % interface_port)
    flask_app.run(port=int(interface_port))
