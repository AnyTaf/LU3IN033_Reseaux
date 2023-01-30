METHODE = ["GET" , "HEAD", "POST" , "PUT" , "DELETE"]
class HTTP :
    def __init__(self):
        self.entete_http = []
        self.corp_http = []
        self.info1 = ""
        self.info2 = ""
        self.info3= ""
        self.code_status=""
        self.message =""
        self.errone= False
        self.isHTTP = True
        self.isRequest = False

    @staticmethod 
    def Couche_HTTP(trame ) : 
         
        def list_octet(trame):
            """
            @param trame : une chaine de caractères d'un ensemble d'octets concatenes 
            @return list_octet : une liste des octets
            """
            list_octet = []
            i = 0
            while i < len(trame)-1 : 
                octet = trame[i] + trame[i+1]
                list_octet.append(octet)
                i += 2
            return list_octet

        def fin_entete_HTTP(list_octet,i):
            """
                Cette fonction return True si on est arrivée à la fin de l'entete, False sinon
            """
            #On teste s'il reste toujour 4 élèments
            if len(list_octet) - i >= 4 :
                list_octet[i] = list_octet[i].lower() #convertit minuscule
                list_octet[i+1] = list_octet[i+1].lower()
                list_octet[i+2] = list_octet[i+2].lower()
                list_octet[i+3] = list_octet[i+3].lower()
                return list_octet[i] == "0d" and list_octet[i+1] == "0a" and list_octet[i+2] == "0d" and list_octet[i+3] == "0a" 
            return True

        def entete_HTTP(trame):
            """
                @param trame : la partie d'une trame qui commence par la couche HTTP
                @return http : une liste de ligne des entetes de HTTP, chaque ligne est une liste de mots
            """
            entete_http = []
            mot_list = []
            mot_str = ""
            i=0
            elem_num = 0
            info1 = ""
            info2 = ""
            info3 = ""
            while not fin_entete_HTTP(trame, i):
                trame[i] = trame[i].lower() #convertit minuscule
                trame[i+1] = trame[i+1].lower()

                if trame[i] == "20": #c'est un espace
                    mot_str += " "
                    mot_list.append(mot_str)
                    if elem_num==0:
                        info1 = mot_str #mettre en code ascii
                    elif elem_num==1:
                        info2 = mot_str
                    elif elem_num==2 :
                        info3 = mot_str
                    mot_str = ""
                    elem_num+=1
                elif trame[i] == "0d" and trame[i+1] == "0a" : #fin d'une ligne de l'entete http
                    mot_list.append(mot_str)
                    entete_http.append(mot_list)#insertion d'une ligne de la requete 
                    mot_str = ""
                    mot_list = []#nouvelle ligne de la requete 
                else :
                    mot_str += chr(int(trame[i],16)) #convertir le code ascii en une lettre
                i+=1
            mot_list.append(mot_str)
            entete_http.append(mot_list)
            return entete_http, i+4,info1,info2,info3 #retour d'index de debut du corps

        def corps_HTTP(trame):
            """
                @param trame : la partie d'une trame qui commence par lle corps de HTTP
                @return http : une liste de ligne du corps de HTTP, chaque ligne est une liste de mots
            """
            corp_http = []
            mot_list = []
            mot_str = ""
            i=0
            while i<len(trame)-1:
                trame[i] = trame[i].lower() #convertit minuscule
                trame[i+1] = trame[i+1].lower()

                if trame[i] == "20": #c'est un espace
                    mot_str += " "
                    mot_list.append(mot_str)
                    mot_str = ""
                elif trame[i] == "0d" and trame[i+1] == "0a" : #fin d'une ligne de l'entete http
                    mot_list.append(mot_str)
                    corp_http.append(mot_list)
                    mot_str = ""
                    mot_list = []
                else :
                    mot_str += chr(int(trame[i],16)) #convertir le code ascii en une lettre
                i+=1
            return corp_http
        http = HTTP() 
        if len(trame)>0 :
            list_octet= list_octet(trame)   
            http.entete_http , index ,http.info1,http.info2,http.info3= entete_HTTP(list_octet)
            if(http.info1.startswith("HTTP/")):
                http.isRequest = False

            elif http.info1.strip() in METHODE :
                http.isRequest = True
            else:
                http.isHTTP = False
            http.corp_http = corps_HTTP(list_octet[index:])
        else :
            http.errone = True
        return http
    
    def info_http(self):
        info = "HTTP : "
        info +=  "{}".format(self.entete_http[0])
        return info
