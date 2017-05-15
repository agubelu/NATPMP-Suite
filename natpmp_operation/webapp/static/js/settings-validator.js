$(function() {

    function checked(el) {
        return el.is(":checked");
    }

    function is_integer(str) {
        return str !== "" && /^\d+$/.test(str);
    }

    function is_port(str) {
        return is_integer(str) && str >= 1 && str <= 65535;
    }

    function is_ipv4(str) {
        if(str === "") return false;

        var spl = str.split(".");
        if(spl.length != 4) return false;

        for(var i = 0; i < 4; i++) {
            var d = spl[i];
            if(!/^\d{1,3}$/.test(d) || d > 255) return false;
        }

        return true;
    }

    function check_list(list, pred) {
        if(list === "") return true;
        var spl = list.split(",");
        for(var i = 0; i < spl.length; i++) {
            if(!pred(spl[i].trim())) return false;
        }

        return true;
    }

    var allow_v0 = $("#id-allow_v0");
    var allow_v1 = $("#id-allow_v1");
    var use_tls = $("#id-allow_tls");
    var force_tls = $("#id-force_tls");
    var strict_tls = $("#id-strict_tls");
    var blacklist_mode = $("#id-blacklist_mode");
    var whitelist_mode = $("#id-whitelist_mode");

    allow_v0.change(function() {
        if(!checked($(this)) && !checked(allow_v1)) {
            $("#id-label-allow_v1").click();
        }
    });

    allow_v1.change(function() {
        if(!checked($(this)) && !checked(allow_v0)) {
            $("#id-label-allow_v0").click();
        }

        if(!checked($(this))) {

            if(checked(use_tls)) {
                $("#id-label-allow_tls").click();
            }
            use_tls.attr("disabled", true);


            if(checked(force_tls)) {
                $("#id-label-force_tls").click();
            }
            force_tls.attr("disabled", true);


            if(checked(strict_tls)) {
                $("#id-label-strict_tls").click();
            }
            strict_tls.attr("disabled", true);

        } else {
            use_tls.attr("disabled", false);
            if(checked(use_tls)) {
                force_tls.attr("disabled", false);
                strict_tls.attr("disabled", false);
            }
        }
    });

    use_tls.change(function() {
        if(!checked(use_tls)) {

            if(checked(force_tls)) {
                $("#id-label-force_tls").click();
            }
            force_tls.attr("disabled", true);


            if(checked(strict_tls)) {
                $("#id-label-strict_tls").click();
            }
            strict_tls.attr("disabled", true);

        } else {
            force_tls.attr("disabled", false);
            strict_tls.attr("disabled", false);
        }
    });

    blacklist_mode.change(function() {
        if(checked(blacklist_mode) && checked(whitelist_mode)) {
            $("#id-label-whitelist_mode").click();
        }
    });

    whitelist_mode.change(function() {
        if(checked(blacklist_mode) && checked(whitelist_mode)) {
            $("#id-label-blacklist_mode").click();
        }
    });

    $("#form-edit-settings").validator({
        custom: {
            'ipv4list': function(el) {
                if(!check_list(el.val(), is_ipv4)) {
                    return "Must be a comma-separated list of valid IPv4 addresses.";
                }
            },

            'portlist': function(el) {
                if(!check_list(el.val(), is_port)) {
                    return "Must be a comma-separated list of valid ports.";
                }
            }
        }
    });

    $("#form-edit-settings").validator('update');

});