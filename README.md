# asoc-zeek

This project provides instructions (this README) for configuring the network monitoring
tool [Zeek](https://zeek.org), to capture and relay network telemetry to AlphaSOCs
Analytics Engine (AE).  Once delivered to AE, telemetry is analyzed for a wide range of
potential network threats.  These threats then trigger detections which can be viewed in
the AlphaSOC Console.  To further simplify this process, a BASH script, `bin/asoc-zeek`,
is also provided.  `bin/asoc-zeek` generates a custom Zeek config file, starts Zeek, and
performs some basic cleanup of Zeek logs on exit.

This guide will cover the steps needed to register with AlphaSOCs Console, manual Zeek
configuration and startup, as well as a quick introduction to `bin/asoc-zeek`.

For further insight into how Zeek works, please visit the Zeek homepage linked above.  For
details about AE, visit:
[AlphaSOCs Analytics Engine](https://docs.alphasoc.com/ae/architecture/).

## Who is this for?

If you're an existing AlphaSOC customer and would like to try Zeek as a network monitoring
tool, this is for you.

If you're not a customer, but are curious about the kinds of threats that AlphaSOC can help
you detect on your network, this is for you as well.

## AlphaSOC Registration

Since this guide focuses on setting up Zeek to work with AE, an AlphaSOC account is
needed to get started.  If you don't have an account, please visit
[Demo | AlphaSOC](https://alphasoc.com/demo/).  You'll receive an email with a verification
link and an **organization ID**.  Be sure to verify the account before continuing.

Once you have an account, please visit: [Console | AlphaSOC](https://console.alphasoc.net)
and sign in with your credentials.  Your **organization ID** (also known as a
**Workspace ID**) will be found at the top of https://console.alphasoc.net/credentials
Copy it to your clipboard for later use.

## SSH/Authentication

Zeek will be configured to use SFTP (with SSH-key authentication) in order to upload
telemetry to AlphaSOC.  Thus, you will want to generate an SSH-key pair (without a
passhphrase) and upload the public key to the *Credentials* page
(https://console.alphasoc.net/credentials) using the *SSH Keys* dialog.  Ensure that the
private key is kept in a readable location on the system from which you will run Zeek,
and also ensure that it will be used when communicating with AlphaSOC.  On UNIX-type
systems, this can be done by modifying `~/.ssh/config` and adding the following:

    Host sftp.alphasoc.net
      HostName sftp.alphasoc.net
      IdentityFile /path/to/SSH-keys/your-key-file

**NOTE:** Because Zeek captures packets from a given interface, Zeek must be run by a user
account with the appropriate permissions.  On Linux systems with kernels supporting
capability bits (ie. `CAP_NET_RAW`), this can be a regular user account, provided the Zeek
binary has been given the appropriate permission (more on this later).  On BSD systems
or Linux systems without capability bit support, it will be easiest to run Zeek as root
or via `sudo`.  In such cases, the generated SSH keys and modified config should reside
in root's home directory (ie. `/root/.ssh`).  On OSX, you would use `sudo`, but the SSH
keys and config would remain in your home directory.  Lastly, BSD systems (including OSX)
can be configured to allow a non-root user to access the packet capture device (`/dev/bpf`)
thus allowing them to run programs such as Zeek.  This is done by adding the desired user
to a group which has been given access to `/dev/bpf`.  Exact instructions on how to do this
are beyond the scope of this guide, but are easily accessible online.

## Installing Zeek

This guide has been tested with Zeek version 4.1.1.  To install Zeek, visit
https://zeek.org/get-zeek/, and follow the instructions for your system.  Once installed,
make sure to add the installation destination to your user path.  Again, this will be
the user that will run Zeek.  For example, if Zeek has been installed to `/opt/zeek/bin`,
add the path via:

    $ export PATH=$PATH:/opt/zeek/bin

You may also add this to your shell's startup script.

## Running Zeek

### Automatically via the `asoc-zeek` Script

If you want to try an automated approach for generating a config file and starting Zeek,
download `asoc-zeek`, found under this projects `bin/` directory, to a location readable
by the user account that will be used to run Zeek.  Then, determine on which interface
you want Zeek to capture packets (ie. via `ip`/`ifconfig`/etc) and finally, where INTF
is the capture interface, run:

    $ /path/to/asoc-zeek -i INTF -o YOUR_ORGANIZATION_ID

For additional usage documentation, see: `/path/to/asoc-zeek --man` and
`/path/to/asoc-zeek --help`

Assuming all went well and `asoc-zeek`, along with Zeek, are running, you can move onto
[Testing](#testing-alphasoc-threat-detection).

### Manually

Zeek deposits its log files in the current working directly.  To keep things clean, it's
best to create a Zeek working directory, and change to that directory before continuing.
Let's assume that the working directory you've created and changed to is `~/.asoc/zeek`.

Create an empty file to house your Zeek config.  You can call this file anything you like
(ie. `~/.asoc/zeek/myconfig.zeek`).  Now, copy-and-paste and template below into your
`myconfig.zeek`.

    module SSL;
    export {
        redef record Info += {
            cert_hash: string &log &optional;
        };
    }
    hook ssl_finishing(c: connection) &priority=5
        {
        if ( c$ssl?$cert_chain && |c$ssl$cert_chain| > 0 && c$ssl$cert_chain[0]?$x509 )
            {
            c$ssl$cert_hash = c$ssl$cert_chain[0]$sha1;
            }
        }

    event zeek_init()
    {
        Log::add_filter(Conn::LOG, [$name="log-conn", $path="conn_logs", $writer=Log::WRITER_ASCII,
               $interv=30sec, $postprocessor=Log::sftp_postprocessor]);
        Log::sftp_destinations[Log::WRITER_ASCII,"conn_logs"] = set([$user="YOUR_ORGANIZATION_ID",$host="sftp.alphasoc.net",$host_port=2222,$path="conn_logs_path"]);

        Log::add_filter(DNS::LOG, [$name="log-dns", $path="dns_logs", $writer=Log::WRITER_ASCII,
               $interv=30sec, $postprocessor=Log::sftp_postprocessor]);
        Log::sftp_destinations[Log::WRITER_ASCII,"dns_logs"] = set([$user="YOUR_ORGANIZATION_ID",$host="sftp.alphasoc.net",$host_port=2222,$path="dns_logs_path"]);

        Log::add_filter(HTTP::LOG, [$name="log-http", $path="http_logs", $writer=Log::WRITER_ASCII,
               $interv=30sec, $postprocessor=Log::sftp_postprocessor]);
        Log::sftp_destinations[Log::WRITER_ASCII,"http_logs"] = set([$user="YOUR_ORGANIZATION_ID",$host="sftp.alphasoc.net",$host_port=2222,$path="http_logs_path"]);

        Log::add_filter(SSL::LOG, [$name="log-ssl", $path="ssl_logs", $writer=Log::WRITER_ASCII,
               $interv=30sec, $postprocessor=Log::sftp_postprocessor]);
        Log::sftp_destinations[Log::WRITER_ASCII,"ssl_logs"] = set([$user="YOUR_ORGANIZATION_ID",$host="sftp.alphasoc.net",$host_port=2222,$path="ssl_logs_path"]);
    }

Using your favourite text editor, replace all instances of *YOUR_ORGANIZATION_ID* with your actual organization id.

Before going any further, make sure your user account (root or otherwise) can authenticate
with AlphaSOC.  To do so, run:

    $ ssh -p 2222 YOUR_ORGANIZATION_ID@sftp.alphasoc.net

If you see output such as `Permission denied (publickey)`, check that the correct SSH
public key has been uploaded to https://console.alphasoc.net/credentials, and that you
are running the SSH command above from the correct user account.  If you still encounter
this problem, read through [SSH/Authentication](#ssh/authentication) carefully to make
sure that your SSH configuration is correct.

If you're running a Linux distribution with kernel support for capability bits, and you
want to run Zeek as a non-root user, you will need to add the appropriate capabilities to
two Zeek executables (`zeek` and `capstats`).  To do so, as root or via `sudo`, run:

    for cmd in zeek capstats; do
        sudo setcap cap_net_raw=eip $(which "$cmd")
    done

Select the network interface on which you want Zeek to capture packets
(ie. via `ip`/`ifconfig`/etc) and, where INTF is the capture interface,
run Zeek as the appropriate user:

    $ zeek -i "INTF" -p "." -U ".status" "myconfig.zeek"

You should see `listening on INTF`.  When traffic is generated, you will also see a message
indicating connection, dns, ip, ssl and/or http logs are being sent to AlphaSOC.

Assuming all went well and Zeek is running, you can move onto
[Testing](#testing-alphasoc-threat-detection).
    
## Testing AlphaSOC Threat Detection

With Zeek running (either manually, or via `asoc-zeek`) and sending telemetry to AlphaSOC,
you can now begin generating some simulated, malicious traffic, in order to see the kinds
of network threats AlphaSOC detects.  The simplest way to generate such traffic, is to
download AlphaSOCs [Network Flight Simulator](https://github.com/alphasoc/flightsim)
and run the suite of simulations on the system where Zeek is capturing packets.  You can
build `flightsim` from source (a recent Go compiler will be needed), or download one of
binary packages from the
[latest release](https://github.com/alphasoc/flightsim/releases/latest).

Once installed, alongside Zeek, start with:

    $ /path/to/flightsim -h

To see a list of simulations that can be run, try:

    $ /path/to/flightsim run -h

To run all available modules, run:

    $ /path/to/flightsim run

Finally, visit [Console | AlphaSOC](https://console.alphasoc.net/) and in the *Dashboard*
an overview of detected network threats should be availalbe.  For a more detailed view,
visit https://console.alphasoc.net/detections

## Shutting Down Zeek

If you started Zeek with `asoc-zeek`, you may simply CTRL-C/kill the `asoc-zeek` process.
Zeek log files will be removed from the working directory, leaving behind the automatically
generated config, `stdout.log` and `stderr.log`.  These files are purposefully left behind.

If you started Zeek manually, CTRL-C/kill the Zeek process.  Log file cleanup is left up
to the user.

## Final Notes

If you have any questions, hit any bugs or discrepancies in the documentation, please
reach out to us on [TODO link to github]() by filing an issue.
