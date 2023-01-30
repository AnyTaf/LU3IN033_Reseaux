# LU3IN033_Reseaux (Visualisateur de trames offline)
### 1. Introduction :
Ce visualisateur est utilisé pour étudier le trafic envoyé sur un réseau déjà capturé.
Il comprend :
* Ethernet (Couche 2)
* IP (Couche 3)
* TCP (Couche 4)
* HTTP (Couche 7)
L'approche utilisé est similaire aux informations produites par Wireshark dans l’outil 'Flow Graph’

### 2. Architecture :
  * La Class Ethernet permet d'extraire toutes les information qui concerne Ethernet.
  * La Class IP permet d'extraire toutes les information qui concerne IP. *
  * La Class TCP permet d'extraire toutes les informations qui concerne TCP, ainsi que le traitement de ses options.
    Elle contient les fonctions qui permettent de calculer chaque champs de ce protocole.
  * La Class HTTP permet de récupèrer l'entete de http et son corps, et d'indiquer si c'est une requete ou bien une réponse http
  * La Class Analyser nous permet de manipuler le fichier .txt où se trouve les trame à étudier ainsi que generer le resultat du visualisateur
		dans un fichier .txt .
  * La Class Analyser.py permet de stocker les trames récupèrées du fichier .txt et de les sauvgarder dans une liste en faisant appelle
		à la fonction (convert_trame_dict), cette fonction est en mesures d'éliminer tous les commentaires en code ascii qui se trouvent dans le fichier
		et de resoudre les differents problemes qui peuvent exister dans une trame.
		Une fois les trames récpérées, ecette classe va faire appelle a la couche ethernet pour generer des trames ethernet qui seront utilisés pour decoder les
		champs des couches superieures.
		Cette classe contient aussi une fonction filter_trame qui permet de filtrer la liste des trames suivant un certains nombre de filtres saisis
		par l'utilisateur
  * IU.py nous permet d'afficher l'interface graphique qui correspond à un graphe de flux TCP.

		

### 3. Structure du code 
Fonctions de nettoyage et validation fichier:
  * read_file(nom_fichier): lis le fichier trace.txt
  * convert_trame_dict(trame): cette fonction a pour but de prendre une trame en entrée ,tester sa validité ,resoudre les differentes anomalies et d'extraire les octets pour les mettre
Fonctions de filtrage:
  * filter_trame( liste_trames,liste_filt ): enlève les commentaires entrelacer ou en fin de ligne
  * get_field(field) : qui permet de verifier si "field" est champs dans une des couche IP ou TCP selon le protocol saisi lors du filtrage(protocol.field==value)
  * detail_flags(flags) : donne les details des flags TCP
  * read_octet(trame,N) : lis N octet de la trame
  * calcul_sequence_number(trame) : calcule de numero de sequence d'un segment TCP
  * calcul_acknowlegement_number(trame) : calcule le numero d'acquittement du segment TCP
  * calcul_data_offset (trame) : calcule de data_offset d'un segment TCP
  * calcul_option(trame , length_option ,tcp):calcule les options d'un segment TCP s'elles existent
  * list_octet(trame) :prend une trame et retourne une liste des octets
  * in_entete_HTTP(list_octet,i) :Cette fonction return True si on est arrivée à la fin de l'entete, False sinon
  * entete_HTTP(trame) : retourne l'entete http
  * corps_HTTP(trame) : retourne le corps de http
Fonctions d'analyse:
	* couche_ethernet(trame) : analyse la trame et détermine si le protocole est est IP ou autre puis renvoi les differents champs de l'entete ethernet
  * couche_IPv4(trame): analyse la séquence IP et détermine les differents champs de l'entete IP.
  * couche_TCP(trame): analyse la séquence TCP si elle existe et calcule à l'aide de fonctions déjà implémentées les differents champs de l'entete TCP.
  * couche_HTTP(trame ) : analyse l'entete et le corps de http si elle existe 			

### 4. Installation :
Installation requise : 
* python3
* pip install tk  : pour pouvoir visualiser l'interface du projet qui a été conçue avec TKinter
* pip install tabulate : pour installer la package tabulate de python

Si vous utilisez un systéme UNIX le code devrait marcher nativement

Si vous utilisez un systéme Windows vous devez installer make sur votre machine pour pouvoir 
executer le makefile
    

### 5. Utilisation :
Pour executer le programme :
* Vous devez vous mettre sur le dossier analyseur avec la commande : cd analyseur
* Executer la commande : make run
* 
    cette commande va lancer le makefile qui lui meme lancera le programme principale IU.py

A l'execution de la commande ```make run``` vous allez avoir :
* une interface graphique qui s'affichera ou vous de devez cliquer sur fichier dans la barre menu en haut à droite ensuite sur ouvrir un fichier
* selectionner un fichier .txt contenant un ensemble de trames
Le graphflow s'affichera ensuite sur l'interface contenant l'ensemble des trames par ordre chronologique qui
correspond à leur ordre d’apparition dans le fichier trace.
Le visiualisateur permet aussi de faire un ensemble de filtre et de génerer deux fichiers
* un fichier texte contenant le resutlat du visualisateur 
* un autre fichier texte contenant les differents resultats de decodage

Synataxe du filtre est la suivante : 

        protocol.field==value 
        protocol.field!=value 
	  protocol
        on peut eventuellement executer des filtres de la forme :
        protocol1.field1==value1 || protocol2.field2==value2 (valable pour cas d'inegalite)

        protocol : {tcp,http,ip}
        field :{
            si protocol ==tcp :{port_src ,port_dest ,sequence_number ,acknowlegement_number }
            si protocol ==ip : { version, protocol, src, dst}
            si protocol ==http : pas de field
        }
