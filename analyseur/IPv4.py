from asyncio.windows_events import NULL
from re import T
from TCP import *

class IPv4 :
    def __init__(self):
        """
            Constructeur de IPv4
        """
        self.errone = False
        self.Version = ""
        self.IHL = ""
        self.TOS = ""
        self.Total_Length = ""
        self.Identification =""
        self.Flags_Fragment_offset = ""
        self.R = ""
        self.DF = ""
        self.MF = ""
        self.Fragment_offset=""
        self.TTL = ""
        self.Protocol = ""
        self.Checksum=""
        self.Source_IP_Addr=""
        self.Destination_IP_Addr=""
        self.taille_option = 0
        self.Option=""
        self.data = None
        self.utilisation_protocol=""
    
    @staticmethod
    def Couche_IPv4(trame):
        ip = IPv4()
        if len(trame)<40 :
            ip.errone = True
        else:
            ip.Version = trame[0:1]
            ip.IHL= trame[1:2]
            if int(ip.IHL,base=16)*4*2 > len(trame) :
                ip.errone = True 
                return ip
            ip.TOS = trame[2:4]
            ip.Total_Length = trame[4:8]
            ip.Identification = trame[8:12]
            ip.Flags_Fragment_offset = trame[12:16]

            flag = bin(int(ip.Flags_Fragment_offset,base=16))[2:]
            flag = flag.zfill(16)

            ip.R = flag[0]
            ip.DF = flag[1]
            ip.MF = flag[2]
            ip.Fragment_offset=int(flag[3:16],base=2)*8
            ip.TTL = trame[16:18]
            ip.Protocol = trame[18:20]
            ip.Checksum = trame[20:24]
            ip
            i = 24
            while i<=39:
                if i<=31:
                    n = int(trame[i],16)*16 + int(trame[i+1],16)
                    if i!=24 :
                        ip.Source_IP_Addr+="."
                    ip.Source_IP_Addr+= str(n)  
                    i+=1
                elif i<=39 :
                    n = int(trame[i],16)*16 + int(trame[i+1],16)
                    if i!=32:
                        ip.Destination_IP_Addr+="."
                    ip.Destination_IP_Addr+= str(n)  
                    i+=1
                i+=1
            ip.taille_option = 4 * int(ip.IHL,16) - 20 
            if ip.taille_option > 0 :
                ip.Option = trame[40:int(ip.IHL,16)*4*2]
            if ip.Protocol == "06":
                ip.utilisation_protocol = "TCP"
                ip.data = TCP.couche_TCP(trame[int(ip.IHL,16)*4*2:])
            elif  ip.Protocol!="01" and ip.Protocol!="08" and ip.Protocol!="11" and ip.Protocol!="1D":
                ip.errone = True
            if ip.Protocol == "01":
                ip.utilisation_protocol = "ICMP"
            elif ip.Protocol == "02":
                ip.utilisation_protocol = "IGMP"
            elif ip.Protocol == "17":
                ip.utilisation_protocol = "UDP"
                
        return ip
    
    def get_field (self ,field) :
        if field == "Version" or field == "version" : 
            return self.Version 
        elif field == "Protocol" : 
            return self.Protocol 
        elif field == "src" : 
            return self.Source_IP_Addr 
        elif field == "dst" : 
            return self.Destination_IP_Addr
        else :
            return ""
        
        