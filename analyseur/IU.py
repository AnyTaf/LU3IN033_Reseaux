from cgitb import grey
from re import L
from tkinter import *
from tkinter import ttk
from tkinter import filedialog
import os
from turtle import right 
from Analyser import *
from TCP import *
from Ethernet import *
from IPv4 import *
from HTTP import *

X = 496
Y = 60
Xi = 248
Yi = 20 
def open_file():
    path = filedialog.askopenfilename(initialdir= os.getcwd(), title = "Selectionnez un fichier .txt", filetypes=(("text files", "*.txt"), ("all files", "*.*")))
    analyser = Analyser(path)
    analyser.creation_output_file()
    update_leftFrame(analyser)

def filtrer(a):
    filtre =""
    filtre = text.get(1.0, END)
    dic_trames , erreur = filter_trame(a.dic_trames,filtre)
    if(not erreur):
        a.analyseTrame(dic_trames)
        update_leftFrame(a)
        label["text"] = "Choisissez un filtre"
        label["fg"] = "black"
    else:
        label["text"] = "Ce filtre n'existe pas"
        label["fg"] = "#f53325"
    return

def refresh(a):
    a.analyseTrame(a.dic_trames)
    update_leftFrame(a)

def update_leftFrame(a):
    label_image.destroy()
    leftFrame.place(x = 0 , y = 0 , width=1000 , height=450)
    #Création d'n scrollBar horizental et verticale pour le frame
    leftCanvas = Canvas(leftFrame , width=1000 , height=450 , bg="#DAF7A6")
    leftCanvas.place(x = 0 , y = 0 , width=1000 , height=450)
    xscrollbar = ttk.Scrollbar(leftFrame, orient="horizontal" , command = leftCanvas.xview)
    yscrollbar = ttk.Scrollbar(leftFrame, orient="vertical" , command = leftCanvas.yview)
    xscrollbar.place(x=0 , y=430 , width=1000)
    yscrollbar.place(x=980 , y=0 , height = 450)
    leftCanvas.configure(xscrollcommand=xscrollbar.set , yscrollcommand=yscrollbar.set)
    frame_l = Frame(leftCanvas)
    #On fait une boucle pour inserer les adresses ip et les fleches
    if (a != None):
        IPs = a.distinctIP()
        trames = a.trames
        #----------------------------affichage des adresses IP-------------------------------
        nbTrames = len(trames)
        for i in range(len(IPs)) :
            ip = Label(frame_l, text = IPs[i] , width= 70,font=("Times", "10", "bold italic") )
            ip.grid(row=0, column=i)
            leftCanvas.create_line(Xi+i*X,Yi,Xi+i*X,Yi+nbTrames*Y, dash = (4, 2) )
        #----------------------------affichage des fleches entre les adresses IP-------------------------------
        for i in range (len(trames)):
            trame = trames[i]
            #recuperer les infos de tcp
            info = trame.data.data.info_tcp()
            adr_ip_src =IPs.index(trame.data.Source_IP_Addr)
            adr_ip_dest = IPs.index(trame.data.Destination_IP_Addr)
            port_src = str(int(trame.data.data.port_src , base=16))
            port_dest = str(int(trame.data.data.port_dest , base=16))
            if adr_ip_src < adr_ip_dest :
                leftCanvas.create_line(Xi+adr_ip_src*X , Yi+40 + i*Y , Xi+adr_ip_dest*X  , Yi+40 + i*Y , fill="#FF5733" )
                point = [ Xi+adr_ip_dest*X -10,Yi+40 + i*Y - 10, Xi+adr_ip_dest*X-10,Yi+40 + i*Y +10,Xi+adr_ip_dest*X,Yi+40 + i*Y ]
                leftCanvas.create_polygon(point,fill="#FF5733")
                leftCanvas.create_text(Xi+adr_ip_src*X -20,  Yi+40 + i*Y , text =port_src ,font=("Times", "10", "bold italic") , fill="#FF5733")
                leftCanvas.create_text(Xi+adr_ip_dest*X +15,  Yi+40 + i*Y , text =port_dest ,font=("Times", "10", "bold italic"),fill="#FF5733")
                leftCanvas.create_text(Xi+adr_ip_src*X +160 ,Yi+40 + i*Y -10 , text= info)
            else :
                leftCanvas.create_line(Xi+adr_ip_src*X , Yi+40 + i*Y , Xi+adr_ip_dest*X  , Yi+40 + i*Y , fill="#4682B4" )
                point = [ Xi+adr_ip_dest*X +10,Yi+40 + i*Y - 10, Xi+adr_ip_dest*X+10,Yi+40 + i*Y +10,Xi+adr_ip_dest*X,Yi+40 + i*Y]
                leftCanvas.create_polygon(point,fill="#4682B4")
                leftCanvas.create_text(Xi+adr_ip_src*X +20,  Yi+40 + i*Y , text =port_src ,font=("Times", "10", "bold italic"),fill="#4682B4")
                leftCanvas.create_text(Xi+adr_ip_dest*X -20,  Yi+40 + i*Y , text =port_dest,font=("Times", "10", "bold italic"),fill="#4682B4")
                leftCanvas.create_text(Xi+adr_ip_dest*X +160 ,Yi+40 + i*Y -10 , text=info)
            
        leftCanvas.create_text(Xi+X +150 ,Yi+40 + (i+2)*Y -10 , text= " ")
        frame_l.update()
        leftCanvas.create_window((0,0) ,window=frame_l, anchor = NW)
        leftCanvas.configure(scrollregion=leftCanvas.bbox(ALL))
        #---------------------------------------------Ajout d'un champ text pour les filtres-------------------------------------
        label.place(x=330 , y=440)

        text.place(x=360 , y=480)

        button.place(x=400 , y=530)
        button_refresh.place(x=10 , y=545)
        button["command"] = lambda: filtrer(a)
        button_refresh["command"] = lambda: refresh(a)

#-----------------------Création d'une fenetre----------------------------------------

fenetre = Tk()
fenetre.geometry('1000x600')
fenetre.update()
fenetre.title("Visualisateur de trames")
fenetre.resizable(height=False , width = False)
   
#------------------------Création d'un Menu-------------------------------------------
menu_principale = Menu(fenetre)
#Création des sous onglets
fichier = Menu(menu_principale , tearoff = 0)
fichier.add_command(label = "Ouvrir un fichier", command = open_file )
fichier.add_separator()
fichier.add_command(label="Quitter", command=quit)
#Création d'un onglet Fichier


menu_principale.add_cascade(label = "Fichier", menu = fichier)
fenetre.config(menu = menu_principale )

photo = PhotoImage(file="Computer-Network.png")
label_image = Label(fenetre , image = photo)
label_image.place(x=0 , y=0 , height=700)

#------------------------Création d'un frame pour le graphe-----------------------------------------
leftFrame = Frame(fenetre, highlightbackground="black" , highlightthickness= 3)

#-----------------------------------------------------------------------------------------------------
button = Button(fenetre, text="Filtrer", font =("Times", "12", "bold italic"),underline = 0 ,width= 15 , height =1, bg="white", fg="black" , activebackground="#4682B4", relief =RAISED   )
text = Text(fenetre , height = 1.5 , width = 30)
label = Label(fenetre , text="Choisissez un filtre",font =("Times", "13", "bold italic"),height = 2 , width = 30)       
button_refresh = Button(fenetre, text="Réinitialiser", font =("Times", "8", "bold italic"),underline = 0 ,width= 9 , height =1, bg="white", fg="black" , activebackground="#4682B4", relief =RAISED   )
    


fenetre.mainloop()  