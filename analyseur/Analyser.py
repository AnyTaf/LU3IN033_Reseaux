import re
from TCP import *
from Ethernet import *
from IPv4 import *
from HTTP import *
from tabulate import tabulate

class Analyser :
    def __init__(self , path):
        self.trames = []
        self.dic_trames=[]
        trace = read_file(path)
        dic = convert_trame_dict(trace)
        for i in range(len(dic)) :
            self.dic_trames.append(dic[i])
            self.trames.append(Ethernet.couche_ethernet(dic[i])) 
    
    def distinctIP(self):
        """
            @return ip : une des différentes ip qui  interagissent dans les trames 
        """
        ip = []
        for t in self.trames:
            ipS = t.data.Source_IP_Addr
            if ipS not in ip:
                ip.append(ipS)
            ipD = t.data.Destination_IP_Addr
            if ipD not in ip:
                ip.append(ipD)
        return ip

    def analyseTrame(self,trames):
        self.trames = []
        for t in trames :
            self.trames.append(Ethernet.couche_ethernet(t)) 
            
    def creation_output_file(self):
        file1 = open("../resultat/decodage_trame.txt","w+")
        file2 = open("../resultat/flow_graph.txt","w+") 
        file1 = open("../resultat/decodage_trame.txt","w+")
        file2 = open("../resultat/flow_graph.txt","w+") 
        self.analyseTrame(self.dic_trames)
        num_trame =0
        for i in range(len(self.trames)):
            info_general_trame = ""
            info_general_trame ="\nTrame numero"+str(num_trame)+":"
            file1.write(info_general_trame)
            info_general_trame ="\n\tEthernet II: \n"
            file1.write(info_general_trame)
            num_trame += 1
            e = self.trames[i]
            if e.errone :
                #print("La trame ", i," est erronée au niveau ethernet")
                info_general_trame = ""
                info_general_trame ="\t\tLa trame "+str(i)+" est erronée au niveau ethernet \n"
                file1.write(info_general_trame)
            else:
                info_general_trame ="\t\tDestination: "+e.adr_dest+"\n"
                file1.write(info_general_trame)
                info_general_trame ="\t\tSource: "+e.adr_sourc+"\n"
                file1.write(info_general_trame)
                info_general_trame ="\t\tType : 0x"+e.type+"("+e.utilisation_type+")"+"\n"
                file1.write(info_general_trame)
                info_general_trame ="\n\tInternet Protocol Version 4:"+"\n"
                file1.write(info_general_trame)
                ip = e.data
                if e.type!="0800":
                    info_general_trame = ""
                    info_general_trame ="\tERREUR LE VISUALISATEUR EST SENSE TRAITER QUE IP"+"\n"
                    file1.write(info_general_trame)
                else :
                    if ip.errone:
                        info_general_trame = ""
                        info_general_trame ="\tLa trame "+str(i)+" est erronée au niveau IP \n"+"\n"
                        file1.write(info_general_trame)               
                    else :
                        info_general_trame ="\t\tVersion:"+str(int(ip.Version,16))+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\tHeader Length:"+str(int(ip.IHL,16)*4)+"  bytes"+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\tType Of Service:"+str(int(ip.TOS,16))+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\tTotal Length:"+str(int(ip.Total_Length,16))+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\tIdentification: 0x"+ip.Identification+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\tFlags: 0x"+ip.Flags_Fragment_offset+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\t\tReserved bit: "+ip.R+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\t\tDon't Fragment: "+ip.DF+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\t\tMore Fragments: "+ip.MF +"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\t\tFragment Offset: "+str(ip.Fragment_offset)+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\tTime to live: "+str(int(ip.TTL,16))+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\tProtocol: "+ip.utilisation_protocol+"("+str(int(ip.Protocol,16))+")"+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\tHeader checksum: 0x"+ip.Checksum+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\tSource: "+ip.Source_IP_Addr+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\tDestination: "+ip.Destination_IP_Addr+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\tTaille options : "+str(ip.taille_option)+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\t\tDetail options : "+str(ip.Option)+"\n"
                        file1.write(info_general_trame)
                        info_general_trame ="\n\tTransmission Control Protocol:"+"\n"
                        file1.write(info_general_trame)
                        if(ip.Protocol != "06"):
                            info_general_trame = ""
                            info_general_trame ="Le programme traite que le protocole TCP "+"\n"
                            file1.write(info_general_trame) 
                        else :
                            tcp = ip.data
                            if tcp.errone :
                                info_general_trame = ""
                                info_general_trame ="ERREUR LE VISUALISATEUR EST SENSE TRAITER QUE LE PROTOCOLE TCP "+"\n"
                                file1.write(info_general_trame) 
                            else:
                                info_general_trame ="\t\tSource Port: "+str(int(tcp.port_src,16))+"\n"
                                file1.write(info_general_trame)
                                info_general_trame ="\t\tDestination Port: "+str(int(tcp.port_dest,16))+"\n"
                                file1.write(info_general_trame)
                                info_general_trame ="\t\tSequence number: "+str(int(tcp.sequence_number,16))+"\n"
                                file1.write(info_general_trame)
                                info_general_trame ="\t\tAcknowledgement number: "+ str(int(tcp.acknowlegement_number,16))+"\n"
                                file1.write(info_general_trame)
                                info_general_trame ="\t\tHeader Length: "+ str(int(tcp.data_offset,16)*4) +" bytes"+"\n"
                                file1.write(info_general_trame)
                                info_general_trame ="\t\tReserved: "+tcp.reserved+"\n"
                                info_general_trame ="\t\tFlags: 0x"+str(tcp.flags)+"\n"
                                file1.write(info_general_trame)
                                info_general_trame ="\t\t\tDetail_flags :"+str(TCP.detail_flags(tcp.flags))+"\n"
                                file1.write(info_general_trame)
                                info_general_trame ="\t\tWindow size value:"+str(int(tcp.window,16))+"\n"
                                file1.write(info_general_trame)
                                info_general_trame ="\t\tChecksum: 0x"+tcp.checksum+"\n"
                                file1.write(info_general_trame)
                                info_general_trame ="\t\tUrgent pointer: "+tcp.urgent_pointeur+"\n"
                                file1.write(info_general_trame)
                                options =[]
                                for k,v in tcp.option.items():
                                        options.append(v)
                                #print("option :    ",options)
                                info_general_trame ="\t\tOptions: ("+str(tcp.length_option)+" bytes)"+"\n"
                                file1.write(info_general_trame)
                                info_general_trame ="\t\t\tDetails Options"+str(options)+"\n"
                                file1.write(info_general_trame)
                                info_general_trame ="\t\tPadding : "+str(tcp.padding)+"\n"
                                file1.write(info_general_trame)
                                info_general_trame ="\n\tHTTP :"+"\n"
                                file1.write(info_general_trame)
                                if tcp.hasHTTP:
                                    http = tcp.data
                                    if http.errone :
                                        info_general_trame = ""
                                        info_general_trame ="\t\tPAS DE HTTP"+"\n"
                                        file1.write(info_general_trame)
                                    elif http.isRequest   : 
                                        info_general_trame ="\t\tMethode: "+http.info1+"\n"
                                        file1.write(info_general_trame)  
                                        info_general_trame ="\t\tUrl: "+http.info2+"\n"
                                        file1.write(info_general_trame)                              
                                        info_general_trame ="\t\tVersion: "+http.info3+"\n"
                                        file1.write(info_general_trame)
                                    else : 
                                        info_general_trame ="\t\tVersion: "+http.info1+"\n"
                                        file1.write(info_general_trame)  
                                        info_general_trame ="\t\tCode_Status: "+http.info2+"\n"
                                        file1.write(info_general_trame)                              
                                        info_general_trame ="\t\tMessage: "+http.info3+"\n"
                                        file1.write(info_general_trame)
                                    
                                    if len(http.corp_http)==0:
                                        info_general_trame ="\t\tCorps_http: PAS DE CORPS HTTP"+"\n"
                                        file1.write(info_general_trame)
                                    else : 
                                        info_general_trame ="\t\tCorps_http: "+http.corp_http+"\n"
                                        file1.write(info_general_trame)
                                else : 
                                    info_general_trame ="\t\tpas de protocol http echangé"+"\n"
                                    file1.write(info_general_trame)
                                
                                
                                
                                dic_details = {"port_src =":tcp.port_src,"port_dest =":tcp.port_dest,"Seq_Num =":tcp.sequence_number,"WIN =":tcp.window}
                                table = [[ip.Source_IP_Addr ,"----------------------------->",ip.Destination_IP_Addr,tcp.info_tcp()]]
                                headers = ["Source_IP_Addr","                               ","Destination_IP_Addr","Details" ]
                                element_tab = tabulate(table, headers='firstrow', tablefmt="outline")
                                file2.write(element_tab)
                                
        file1.close() 

        file2.close() 


def read_file(name):
    try :
        file = open(name, "r")
        lines = file.readlines()
        return lines
    except:
        print("Le fichier ",name," n'existe pas.")
        return read_file(name)
    

def convert_trame_dict(trame) :
    """
        cette fonction a pour but de prendre une trame en entrée et d'extraire les octets pour les mettre
        dans un dictionnaire en sortie
    
        @Param : trame : ligne du fichier .txt en entrée contenant la trame à convertir
        @Return : trame_dict : dictionnaire contenant les octets en sortie
        
    """
    trame_dict = {} #dictionnaire des trames
    nb_octet_read = 0 
    nb_trame_read = 0
    start_lign = 0
    offset = 0
    lastOfsset = 0
    octet_read = ""
    for lign in trame :
        lign = lign.rstrip()
        if(len(lign)!=0):
            isOffset = True
            error = False
            lign_splitted = lign.split(" ")
            for octet in range(len(lign_splitted)):
                if(len(lign_splitted[octet])>0): 
                    try:
                        int(lign_splitted[octet] , 16)
                    except:
                        error = True
                        break
                    if isOffset :
                        isOffset =False
                        if(len(lign_splitted[octet])!=4): 
                                error = True #la taille de l'offset est différente de 4
                                break
                        try:
                            offset =int(lign_splitted[octet] , 16)
                        except:
                            error = True #la taille de l'offset n'est pas un hexa
                            break
                        if offset==0 :
                            if(len(octet_read)>=10 and not error):
                                trame_dict [nb_trame_read] = octet_read
                                nb_trame_read+=1
                            nb_octet_read = 0
                            lastOfsset = 0
                            octet_read =""
                            error=False
                        elif error :
                            break
                        #tester si l'offset est valide
                        elif lastOfsset+nb_octet_read == offset :
                            lastOfsset += nb_octet_read
                            nb_octet_read = 0
                        else :
                            if(len(octet_read)>=10):
                                trame_dict [nb_trame_read] = octet_read
                                nb_trame_read+=1
                            error = True
                            octet_read =""
                            break
                    elif octet==1 or octet==2 : #vérifier s'il y a 3 espaces aprés l'offset
                        if lign_splitted[octet]!="":
                            error = True
                            break
                        else:
                            continue
                    elif not error :
                        if ( len(lign_splitted[octet])==2  ) :
                            try:
                                o =int(lign_splitted[octet] , 16)
                                nb_octet_read +=1
                                octet_read += lign_splitted[octet]
                            except:
                                error = True #l'octet lu n'est pas en hexa
                                octet_read=""
                        else:
                            error = True
                            #ajouter une
                            octet_read=""
                    else :
                        break
                elif octet!=1 and octet!=2 :
                    error = True
                    break
    
    if (len(octet_read)>=10 ):
        trame_dict [nb_trame_read] = octet_read
    return trame_dict


   
   

def filter_trame( trames,list_filter ):
    #il faut recuperer la liste des filtres dans une liste chaque element est un filtre 
    """
    cette methode retourne la liste des trames qui verifient le filtre inséré
    @param : 
        list_trame : liste de trames
        list_filter : liste de filtre , un filtre doit etre de la forme protocol.field == value
    @return : 
        list_trame_result : la liste des trames qui verifient les filtres s'elles existent
    
    """
    error = False
    egal ="=="
    inegal="!="
    OR =0
    list_trame_result = []
    exist = 0
    tmp = re.split('\s+',list_filter) #cas de filtre avec && ou ||
    
    if len(tmp)>1 : #s'il ya plus d'un filtre
        
        filters= re.split(r"\s(?:&&|\|\|)\s",list_filter) #split selon && ou ||
        if "||" in list_filter : 
            OR =1
        else : 
            OR = 0
    else :
        #cas d'un seul filtre
        filters = []
        filters.append(list_filter)
    for trame in trames :
        for filtr in filters :
            exist =0
            if egal in filtr :
                proto_field, value =  re.split('\==',filtr)
                protocol , field  = re.split('\.',proto_field)
                value = value.strip()
            elif inegal in filtr :
                proto_field, value =  re.split('\!=',filtr)
                protocol , field  = re.split('\.',proto_field)
                value = value.strip()
            else :
                filtr=filtr.strip() # cas de filtre : http, tcp
                if filtr =="http" or filtr=="HTTP":#cas http
                    protocol = "http"
                    print("c bien un filtre http ")
                elif filtr =="tcp" or filtr=="TCP": 
                    protocol = "tcp"
                else :
                    print("ERREUR CE FILTRE EST INEXISTANT")
                    error=True
                    return [] , error
            
            ip = IPv4.Couche_IPv4(trame[28:])
            if not(ip.errone):
                if ip.Protocol=="06" and not (ip.data.errone) :
                    tcp =  ip.data
                    if protocol == "TCP" or protocol == "tcp" :
                        protocol = "06"
                        value = int(value,10)
                        if ip.Protocol == protocol :
                            if egal in filtr:
                                if int (tcp.get_field(field),16) == value :
                                    exist =1
                            else :
                                if int (tcp.get_field(field),16) != value :
                                    exist =1
                    elif protocol == "http" :
                        if tcp.hasHTTP and not tcp.data.errone:
                            print("tcp.hasHTTP")
                            exist =1
                    #quand c du http suffit juste de mettre comme filtre TCP.port_src==80
                    elif protocol=="IP" or protocol=="ip" :
                        if egal in filtr:
                            if ip.get_field(field) == value.strip() :
                                exist =1
                        else:
                            if ip.get_field(field) != value.strip() :
                                    exist =1
                    if exist == 1 :
                        if len(filters)==1  : 
                            list_trame_result.append(trame) 
                        elif OR ==1:
                            list_trame_result.append(trame)
                            break           
    return list_trame_result , error
