from HTTP import *

class TCP : 
    
    def __init__(self ): 
        self.errone = False
        self.port_src = ""
        self.port_dest = ""
        self.sequence_number = ""
        self.acknowlegement_number = ""
        self.data_offset = ""
        self.reserved = ""
        self.flags = []
        self.window = ""
        self.checksum = ""
        self.urgent_pointeur = ""
        self.option = {}
        self.length_option = 0
        self.padding = ""
        self.data = None
        self.hasHTTP= False
        self.MSS=""
        
        
        
    def get_field (self ,field) :
        if field == "port_src" : 
            return self.port_src
        elif field == "port_dest" : 
            return self.port_dest
        elif field == "sequence_number" :
            return self.sequence_number
        elif field == "acknowlegement_number" : 
            return self.acknowlegement_number
        elif field == "data_offset" : 
            return self.data_offset
        elif field == "reserved" : 
            return self.reserved
        elif field == "flags" : 
            return self.flags
        elif field == "window" : 
            return self.window
        elif field == "checksum" : 
            return self.checksum
        elif field == "urgent_pointeur" : 
            return self.urgent_pointeur
        elif field == "option" : 
            return self.option
        elif field == "length_option" : 
            return self.length_option
        elif field == "padding" : 
            return self.padding
        elif field == "data" : 
            return self.data
        else :
            return "" 
    @staticmethod
    def detail_flags(flags) :
        flag_dic = {"URG":"" , "ACK":"", "PSH":"", "RST":"","SYN":"" ,"FIN":""}
        if flags[0] == '1' :
            flag_dic["URG"] = "1"
        else :
            flag_dic["URG"] = "0"

        if flags[1] == '1' :
            flag_dic["ACK"] = "1"
        else :
            flag_dic["ACK"]= "0"
    
        if flags[2] == '1' :
            flag_dic["PSH"] = "1"
        else :
            flag_dic["PSH"] = "0"

        if flags[3] == '1' :
            flag_dic["RST"] = "1"
        else :
            flag_dic["RST"] = "0"
    
        if flags[4] == '1' :
            flag_dic["SYN"] = "1"
        else :
            flag_dic["SYN"] = "0"

        if flags[5] == '1' :
            flag_dic["FIN"] = "1"
        else :
            flag_dic["FIN"] = "0"
    
        return flag_dic 
       
    @staticmethod   
    def couche_TCP(trame):
        """
        cette fonction prend une trame est retourne les champs du segment TCP 
        @Param : trame de données
        @Return : dictionnaire des champs du segment TCP
        """
        tcp = TCP()
        if len(trame)<40 :
            tcp.errone = True
            return tcp
        #calcul du port source 
        #les fonctions internes    
        def read_octet(trame,limit) :
            octet_read = 0
            str = ""
            for octet in trame : 
                if octet_read == limit :
                    break
        
                str =  str + octet
                octet_read +=1 
            return str 
    
        def calcul_sequence_number(trame) :
            sequence_number = ""
            for i in range(8):
                sequence_number = sequence_number + str(trame[i])
            return sequence_number 
    
        def calcul_acknowlegement_number(trame) : 
            acknowlegement_number = ""
            for i in range(4):
                acknowlegement_number = acknowlegement_number + str(trame[i])
            return acknowlegement_number  
      
        def calcul_data_offset (trame) :
            return str(trame[0][0])
    
        def calcul_option(trame , length_option ,tcp) :
        
            octet_read = ""
            length = ""
            option_dic ={}
            i=0
            while i <= length_option -1:
                kind = trame[i]
                kind = kind + trame[i+1]
                if kind == "00" :
                    option_dic [i] = kind + " End of Option List .\n"
                    i = i +2*1
                elif kind == "01": 
                    option_dic [i] = kind + "No-Operation .\n"
                    i = i +2*1
                elif  kind == "02":
                    octet_read = trame[i +2*2: i+4*2]
                    option_dic [i] = kind +"Maximum Segment Size :" +octet_read + ".\n"
                    i = i + 4*2
                elif  kind == "03":
                    octet_read = trame[i +2*2: i+3*2]
                    option_dic [i] = kind + "WSOPT - Window Scale :" +octet_read + ".\n"
                    i = i + 3*2
                elif  kind == "04":
                    octet_read = trame[i +2*2: i+2*2]
                    option_dic [i] = kind + "SACK Permitted :" +octet_read + ".\n"
                    i = i + 2*2
                elif  kind == "05":
                    length = trame[i+2:i+4]
                    length = int(length, 16)
                    octet_read = trame[i+length-2*2 : i+length*2]
                    option_dic [i] = kind + str(length) +"SACK (Selective ACK) :" +octet_read + ".\n"
                    i = i +int(length,16)*2 
                elif  kind == "06":
                    octet_read = trame[i +2*2: i+6*2]
                    option_dic [i] = kind + "Echo (obsoleted by option 8) :" +octet_read + ".\n"
                    i =i +6*2
                elif  kind == "07":
                    octet_read = trame[i +2*2: i+7*2]
                    option_dic [i] = kind + "Echo Reply (obsoleted by option 8) :" +octet_read + ".\n"
                    i = i+ 7*2
                elif  kind == "08":
                    octet_read = trame[i+2*2 : i+10*2]
                    option_dic [i] = kind + "TSOPT - Time Stamp Option :" +octet_read + ".\n"
                    i = i +10*2
                elif  kind == "09":
                    octet_read = trame[i +2*2: i+2*2]
                    option_dic [i] = kind + "Partial Order Connection Permitted :" +octet_read + ".\n"
                    i = i + 2*2
                elif  kind == "0a":
                    octet_read = trame[i +2*2: i+3*2]
                    option_dic [i] = kind + " Partial Order Service Profile :" +octet_read + ".\n"
                    i = i+3*2
                elif  kind == "0b":
                    option_dic [i] = kind + " CC" + ".\n"
                    i =i+2
                elif  kind == "0c":
                    option_dic [i] = kind + " CC.NEW " + ".\n"
                    i = i+2
                elif  kind == "0d":
                    option_dic [i] = kind + "CC.ECHO " + ".\n"
                    i = i+2
                elif  kind == "0e":
                    octet_read = trame[i +2*2: i +3*2]
                    option_dic [i] = kind +" TCP Alternate Checksum Request :" +octet_read + ".\n"
                    i = i+3*2
                elif  kind == "0f":
                    length = trame[i+2:i+4]
                    length = int(length, 16)
                    octet_read = trame[i+length-2: i+length*2]
                    option_dic [i] = kind +" TCP Alternate Checksum Data :" +octet_read  + ".\n"
                    i = i +int(length,16)*2 
                else:
                    tcp.errone = True
                    return option_dic
              
            return option_dic 
                
    #-------------------------------------------------------------------   
        tcp.port_src = read_octet(trame,4) 
        tcp.port_dest = read_octet(trame[4:],4)
        tcp.sequence_number = calcul_sequence_number(trame[8:])
        tcp.acknowlegement_number = calcul_acknowlegement_number(trame[16:])
        tcp.data_offset = calcul_data_offset(trame[24:])
        if int(tcp.data_offset,base=16)*4*2 > len(trame) :
                tcp.errone = True 
                return tcp
        tmp = read_octet(trame[25:],2)
        tmp = bin(int(tmp,16))[2:].zfill(len(tmp)*4)
        liste =[]
        for elem in tmp :
            liste.append(elem)
    
        for i in range(0,6) :
            tcp.reserved = tcp.reserved + str(liste[i])
    #--------------------------------------------------------------------
        tmp = read_octet(trame[26:],2)
        tmp = bin(int(tmp,16))[2:].zfill(len(tmp)*4)
        liste =[]
        for elem in tmp :
            liste.append(elem)
    
        for i in range(2,8) :
            tcp.flags .append(str(liste[i]))
    #--------------------------------------------------------------------
        tcp.window = read_octet(trame[28:],4)
        tcp.checksum = read_octet(trame[32:],4)
        tcp.urgent_pointeur = read_octet(trame[36:],4)
        tcp.length_option = int(tcp.data_offset,16)*4 - 20
        tcp.option = calcul_option(trame[40:], tcp.length_option,tcp)
        if not tcp.errone:
            tcp.padding = int(tcp.length_option % 4) #nombre d'octet de padding est multiple de 4
            if len(trame)>int(tcp.data_offset,16)*4 :
                tcp.data =  HTTP.Couche_HTTP(trame[(20+tcp.length_option)*2:])
                if not tcp.data.isHTTP :
                    tcp.data=trame[(20+tcp.length_option)*2:]
                else:
                    tcp.hasHTTP = True
        
        return tcp

    def info_tcp(self):
        if self.hasHTTP and not self.data.errone:
            return self.data.info_http()
        info = "TCP : "
        info +=  str(int(self.port_src,  base=16) )+ " -> " + str(int(self.port_dest,base=16))+ " "
        flag_dic =[]
        if self.flags[0] == '1' :
            flag_dic.append("URG")
        if self.flags[1] == '1' :
            flag_dic.append("ACK")
        if self.flags[2] == '1' :
            flag_dic.append("PSH")
        if self.flags[3] == '1' :
            flag_dic.append("RST")
        if self.flags[4] == '1' :
            flag_dic.append("SYN")
        if self.flags[5] == 1 :
            flag_dic.append("FIN")
        if len(flag_dic)>0:
            info +=  "{}".format(flag_dic)
        info += " Seq="+str(int(self.sequence_number ,  base=16))
        if self.flags[1] == 1 :
            info += " Ack="+str(int(self.acknowlegement_number, base=16))
        info += " Win="+str(int(self.window, base=16))
        if self.length_option > 0  : #and mss
            if len (self.MSS) >0 :
                info += " MSS="+str(int(self.MSS,16))
        return info

    
    

            