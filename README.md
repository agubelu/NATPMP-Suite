# NAT-PMP Suite

## About

This is a NAT-PMP implementation that includes additional features, such as an enhanced, non-official version which allows secure requests and support for multiple public interfaces.

A NAT-PMP client and additional utilities are also provided, like a web-based administrative interface and performance measurement scripts.

## Requirements

- Python 3.5.2
- nftables >= 0.5
- OpenSSL >= 1.0.2g
- Python dependencies listed in requirements.txt (can be installed using pip)

## NAT-PMP Service

To launch the NAT-PMP service, you must execute the file *natpmp_daemon.py*. The basic structure of the command to be executed is as follows:

`sudo ./natpmp_daemon.py [args...]`

`sudo` is required in order to allow the service to make port mappings using nftables.

The following arguments are allowed:

- **-h / --help**: Displays a help tooltip and finishes the execution.
- **-file / --use-settings-file**: Uses the settings file instead of argument-based configuration. Any other arguments will be ignored.
- **-p / --private-interfaces [addresses...]**: Sets the IPv4 addresses corresponding to the private interfaces in which the service will listen for requests. This argument must include one or many IPv4 addresses separated by spaces.
- **-u / --public-interfaces [addresses...]**: Sets the IPv4 addresses corresponding to the public interfaces in which the service will make port mappings. This argument must include one or many IPv4 addresses separated by spaces.
- **-v0 / --version0**: Allows NAT-PMP v0 (official, defined by RFC 6886) requests.
- **-v1 / --version1**: Allows NAT-PMP v1 (enhanced, unofficial) requests.
- **-sec / --allow-security**: Allows secure requests when using NAT-PMP v1.
- **-fsec / --force-security**: If this argument is included, all non-secure v1 requests will be denied.
- **-s / --strict-certs**: If this argument is included, only certificates issued by the provided utility will be allowed.
- **-minp / --min-port [port]**: Sets the lowest public port available for mappings.
- **-maxp / --max-port [port]**: Sets the highest public port available for mappings.
- **-x / --excluded-ports [ports...]**: Sets specific public ports that are not available for mappings, even if they are inside the previously defined range. This argument must include one or many ports separated by spaces.
- **-minl / --min-lifetime [seconds]**: Sets the minimum allowed lifetime for port mappings.
- **-maxl / --max-lifetime [seconds]**: Sets the maximum allowed lifetime for port mappings.
- **-fixedl / --fixed-lifetime [seconds]**: Sets a fixed lifetime for port mappings. minl and maxl will be ignored.
- **-b / --blacklist**: Activates the blacklist mode, denying all requests from specific addresses.
- **-bl / --blacklisted-addresses [addresses...]**: Sets the IPv4 addresses whose requests will be denied if the blacklist mode is on.
- **-w / --whitelist**: Activates the blacklist mode, accepting only requests from specific addresses and denying all other requests.
- **-wl / --whitelisted-addresses [addresses...]**: Sets the IPv4 addresses whose requests will be accepted if the whitelist mode is on.
- **-web [port] [password]**: If this argument is passed, the administrative web interface will be enabled. This argument must include the port in which the web interface will be enabled and the administrative password.
- **-debug**: Activates the debug mode, printing the mapping statuses after every requests and all web interface accesses.

If the `-file` argument is used, the service will use the parameters defined in settings.py instead of the passed arguments.

## NAT-PMP Client

The NAT-PMP client can be accessed through the file *natpmp_client.py* and includes a graphical user interface. If the file is executed through double-click or without any arguments, the GUI will be launched. Otherwise, it can be used through the command line. The basic syntax for the command to be executed is as follows:

`./natpmp_client.py [args...]`

The following arguments are allowed:

- **-h / --help**: Displays a help tooltip and finishes the execution.
- **-v0**: Sends a NAT-PMP v0 (official) request.
- **-v1**: Sends a NAT-PMP v1 (enhanced) request.
- **-info**: Sends an information (public addresses) request for the desired version.
- **-req [private_port] [public_port] [TCP/UDP]**: Sends a mapping request for the desired version, private port, public port and protocol. If it's a NAT-PMP v1 request, the `-ips` argument must also be included.
- **-l [seconds]**: Sets the requested lifetime for the mapping request.
- **-ips [addresses...]**: In the v1 (enhanced) NAT-PMP version, all mapping requests must include the public IPv4 interfaces to map to. They can be defined using this argument, including them as space-separated parameters.
- **-sec [cert] [key]**: Send a secure request (only allowed in NAT-PMP v1), must include the paths to the certificate and private key to be used.
- **-g [address]**: Manually specify the gateway address to send the NAT-PMP request to. If this argument is not included, the client will try to automatically find the default gateway address.

## Certificate creation

When issuing secure NAT-PMP request, a client certificate and the corresponding private key are required in order to cipher and sign the request. This NAT-PMP suite includes a certificate creation utility that can be used through the "create_cert.py" file using the following command:

`sudo ./create_cert.py client_address lifetime [size] [-der]`

`sudo` is required in order to be able to read the service private key, used to sign the client certificates.

The following arguments are allowed:

- **client_address**: IPv4 address of the client that will use the certificate. This argument is mandatory.
- **lifetime**: Amount of time, in seconds, in which the certificate will be considered valid. An expired certificate will be rejected, even if it's sintactically valid.
- **size**: Length in bits of the RSA modulus to use. Accepted values are 1024, 2048 and 4096 (defaults to 2048).
- **-der**: If this argument is included, the certificate will be stored using the binary DER format. Otherwise it will be stored as a plain-text PEM file.

Before using this utility, the NAT-PMP service must have been executed at least once using the `-sec` argument, in order to allow for the root certificate and private key to be generated. All certs and keys generated using this utility will be stored in the `certs/` directory, and can be safely deleted from that folder once they have been delivered to the client.

## Resource usage measurement

It's posibble to run the NAT-PMP service while measuring the system resources that it consumes in terms of RAM and CPU. To achieve this, a Shell utility is provided, and it can be executed using:

`sudo ./run_and_measure.sh`

This will execute the service with the `-f` parameter (using the configuration from settings.py) and will take a CPU and RAM usage snapshot every second.

If executed using this utility, the NAT-PMP service will not display any console output. Insice the `performance_output/` directory two new files will be generated: 
*daemon_output.txt*, which will contain the usual daemon output, and *performace_data.txt*, which holds the resource usage data.

The latter file will contain an initial line with the service startup timestamp, and an additional line for each second the service has been running, with the following data: % use of CPU until that moment, % of RAM usage, total CPU usage time and total execution time.

## Response time measurement

In addition to measuring resource usage, you can also monitorize the response times of the NAT-PMP service using another provided utility that sends many NAT-PMP requests and display statistics regarding the service response rates.

Said utility is located in the *measure_performance.py* file and can be executed as follows:

`./measure_performance.py [args...]`

The following arguments are allowed:

- **-h / --help**: Displays a help tooltip and finishes the execution.
- **-v [version]**: NAT-PMP version to use, defaults to 0.
- **-n [amount]**: Number of NAT-PMP requests to send, defaults to 1000.
- **-t [millis]**: Amount of time in milliseconds after which a request is considered timed out and therefore failed. Defaults to 1000.
- **-g [address]**: IPv4 address of the gateway to send the requests to. This argument is mandatory.
- **-op [info/req]**: NAT-PMP operation to request. Can be either an information request or a port-mapping request. If requesting port mappings, port numbers are set to a random value every request.
- **-ips [addresses...]**: If the port mapping operation is requested using NAT-PMP v1, this argument is mandatory and must include a space-separated list of public IPv4 addresses to map to.
- **-sec [cert] [key]**: Send secure requests in NAT-PMP v1 instead of normal requests. Must include the cert and key path to use.
