from IPv4 import *

class Ethernet : 
    def __init__(self ) :
        self.errone = False
        self.adr_dest = ""
        self.adr_sourc = ""
        self.type = ""
        self.utilisation_type = ""
        self.data = None

    @staticmethod    
    def couche_ethernet(trame) :
        """
            cette fonction traite une trame au niveau de la couche ethernet 
            @Param : trame
            @Return :  les valeurs des attributs suivant: "adr_dest":"", "adr_sourc":"","type":"","utilisation type":""
        """
        ethernet = Ethernet()
        #la trame ethernet est sur 6 + 6 +2 =14 octet
        if(len(trame)< 28):
            ethernet.errone = True
        else :
            for cpt in range (0,28) :
                if cpt < 12 : 
                    # adresse MAC destination 
                    if cpt % 2 == 0 :
                        ethernet.adr_dest += trame[cpt]
                    else :
                        ethernet.adr_dest += trame[cpt] + ":"
                
                elif cpt < 24 :
                    #adresse MAC source
                    if cpt % 2 ==0 :
                        ethernet.adr_sourc += trame[cpt]
                    else :
                        ethernet.adr_sourc += trame[cpt] + ":"  
                elif cpt < 28 :
                    #type
                    ethernet.type += trame[cpt]
                    
            #utilisation du type selon sa valeur 
            type_ethernet = ethernet.type
            if type_ethernet =="0800" :
                ethernet.utilisation_type = "IPV4"
                ethernet.data = IPv4.Couche_IPv4(trame[28:])
            else:
                if type_ethernet =="0805" :
                    ethernet.utilisation_type = "X.25 niveau 3"
                elif type_ethernet =="0806" :
                    ethernet.utilisation_type = "ARP"
                elif type_ethernet =="0835" :
                    ethernet.utilisation_type = "RARP"
                elif type_ethernet =="0898" :
                    ethernet.utilisation_type = "Appletalk"
                else :
                    ethernet.errone = True
            
        return  ethernet    
         
             