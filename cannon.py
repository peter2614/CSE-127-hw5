from pox.lib.packet.ipv4 import ipv4
import re

class Cannon(object):
    
    def __init__ (self, target_domain_re, url_path_re, iframe_url):
        self.target_domain_re = target_domain_re
        self.url_path_re = url_path_re
        self.iframe_url = iframe_url
        self.dict = {}

    # Input: an instance of ipv4 class
    # Output: an instance of ipv4 class or None
    def manipulate_packet (self, ip_packet):
        print "src = ", ip_packet.srcip
    	print "dst = ", ip_packet.dstip

        # only care about HTTP
        tcp = ip_packet.find('tcp')
        if not tcp:
            return ip_packet

        tcpContent = tcp.next

        # get domain
        domain = tcpContent[tcpContent.find("Host: ")+6 : tcpContent.find("\r\n", tcpContent.find("Host: "))]

        # get url
        url = tcpContent[tcpContent.find("GET ")+4 : tcpContent.find("HTTP", tcpContent.find("GET "))-1]

        domainMatch = bool(self.target_domain_re.search(domain))
        pathMatch = bool(self.url_path_re.search(url))

        # request & response tuples (Create a mapping between the client/server IP/port and the domain)
        req = (ip_packet.srcip, ip_packet.dstip, tcp.srcport, tcp.dstport)
        res = (ip_packet.dstip, ip_packet.srcip, tcp.dstport, tcp.srcport)

        # if Accept-Encoding is already there
        if "Accept-Encoding: " in tcpContent:
            start = tcpContent.find("Accept-Encoding: ") + 17
            end = tcpContent.find("\r\n", start)
            # print "packet: " + tcpContent[start:end]

            packet.set_payload(packet.next.replace(packet.next[start : end], "identity"))
            # self.offset = 8 - (end - start) # length of "identity" = 8

        # if Accept-Encoding is not there
        else:
            noCompress = "Accept-Encoding: identity"
            headers = tcpContent.split('\r\n')
            headers.insert(len(headers)/2, noCompress)
            tcpContent = '\r\n'.join(headers)
            tcp.next = tcpContent
            # print tcpContent

        
        # if domainMatch & pathMatch:
            # iframeContent = "<iframe src=" + self.iframe_url + "></iframe>"
            
        # if self.url_path_re.search(url) and self.target_domain_re.search(currDomain):
           
        

        # isRequest = bool(re.match('^(GET|POST|PUT|DELETE)\s+.+', tcp.next))
        # # get http request
        # if isRequest:
        #     req = tcp.next
        #     noCompress = "Accept-Encoding: identity"


        #     headers = req.split('\r\n')
        #     headers.insert(len(headers)/2, noCompress)
        #     req = '\r\n'.join(headers)  
        #     print req
            
        # isResponse = bool(re.match('^HTTP/1.1.+', tcp.next))
        # if isResponse:
        #     res = tcp.next
            # domain and path must match
            # domainMatch = bool(self.target_domain_re.match('1'))
            # pathMatch = bool(self.url_path_re.match('1'))
            # if domainMatch & pathMatch:
            #     iframeContent = "<iframe src=" + self.iframe_url + "></iframe>"
            #     print iframeContent
            # print res

    	# Must return an ip packet or None
    	return ip_packet


