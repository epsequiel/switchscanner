#! /usr/bin/python


#import xml.sax


#-------------------------------------------------------------------------------
# Colores
#

class bcolors:
    HEADER = '\033[38;5;118m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CONSOLE = '\033[38;5;034m'
    VERDE = '\033[38;5;046m'
    AQUA = '\033[38;5;048m'
    VERDEBOLD = '\033[38;5;048m'
    _VIOLETA = "\e[38;5;201m"
    _NARANJA = "\e[38;5;208m"
    _VERDE = "\e[38;5;048m"
    _ROJO = "\e[38;5;196m"
    _NC = "\033[0m"


from libnmap.parser import NmapParser
import telnetlib

#-------------------------------------------------------------------------------
# default_cred_check
# Uso: una vez que encontramos un host escuchando telnet probamos si ademas
# tiene las credenciales default.
# Input: host address
# Output: si el login es positivo devuelve el prompt o system info
def default_cred_check(host):
    user = "admin"
    password = "switch"
    response = "If you see this message,\nthe programmer's wife made a mistake... :("
    try:
        tn = telnetlib.Telnet(host,timeout=2)
     except socket.error, e:
        response = e[1]
        print response
    (i,obj,res) = tn.expect(["login :"],2)
    if i != 0:
        # no es Alcatel
        return "No vulnerable"
    tn.write(user + "\n")
    (i,obj,res) = tn.expect(["password : "],2)
    if i != 0:
        # no es Alcatel o hubo otro problema
        return "No vulnerable"
    tn.write(password + "\n")

    # Descripcion del sistema
    t = ''
    tn.write("show system" + "\r\n")
    while tn.sock_avail():
        r = tn.read_eager()
        t += r
        print r,

    return "Vulnerable"

#    tn.read_until("login:",3)
#    tn.write(user + "\n")
#    tn.read_until("password:",3)
#    tn.write(password + "\n")
#    # Login exitoso?
#    tn.write("ls\n")
#    print tn.read_some()
#    tn.write("exit\n")
#    print tn.read_all()

nmap_report = NmapParser.parse_fromfile('10.7.1.0-24.xml')
print "Nmap scan summary: {0}".format(nmap_report.summary)

# warrning ports: puertos no convenientemente abiertos
wp = [21,23,80]

for scanned_hosts in nmap_report.hosts:
        print scanned_hosts
for _host in nmap_report.hosts:
    if _host.is_up():
        print "\n"
        print bcolors.HEADER + \
                "++++++ Host: %s %s ++++++" % (_host.address,_host.hostnames) \
                + bcolors._NC
        for s in _host.services:
            print "-->    Service:\t %s/%s (%s)" % (s.port,s.protocol,s.state),
            # si es un puerto no deseado
            if s.port in wp:
                print bcolors.WARNING + "WARNING" + bcolors._NC
            else:
                print ""
            # NmapService.cpelist returns an array of CPE objects
            for _serv_cpe in s.cpelist:
                print "-->        CPE: %s " % (_serv_cpe.cpestring)

        if _host.os_fingerprinted:
            print "  OS Fingerprints"
            for osm in _host.os.osmatches:
                print "[*]    Found Match:%s (%s)" % (osm.name,osm.accuracy)
                # NmapOSMatch.get_cpe() method return an array of string
                # unlike NmapOSClass.cpelist which returns an array of CPE obj
                for cpe in osm.get_cpe():
                    print "\t    CPE: %s" % cpe

for scanned_hosts in nmap_report.hosts:
        print scanned_hosts.address
