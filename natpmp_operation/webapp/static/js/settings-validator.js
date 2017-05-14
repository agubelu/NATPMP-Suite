$(function() {

    function checked(el) {
        return el.is(":checked");
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
            force_tls.attr("disabled", false);
            strict_tls.attr("disabled", false);
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

});