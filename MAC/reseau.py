# -*- coding: utf-8 -*-

import numpy as np 
import csv
import matplotlib
import random
from dateutil.relativedelta import relativedelta 


"""
Une fonction qui  convertit un fichier de trames en un dictionnaire de chaine de caractére 
:trame : la trame à convertir 
: return : un dictionnaire de chaine de caractére 
"""
def trame_to_ligne(trame):
    liste_trame={}
    nb_trame=0
    s=""
    nb_octet_lu=0
    nb_ligne=0
    #parcourir le tableau de trames
    for ligne in trame:
        debut_ligne=0
        for octet in ligne.split():
            if debut_ligne == 0:
                try :
                    offset= int(octet,16)
                except :
                    break

                #debut de la trame
                if offset==0:
                    nb_octet_lu=0
                    nb_ligne=0
                    #debut de la ligne : on ajoute la trame si elle n'est pas vide
                    if s!="" :
                        liste_trame[nb_trame]=s
                        nb_trame+=1
                    s=""
                # pas au debut de la trame
                else:
                    #Ignorer la suite de la trame
                    if offset < nb_octet_lu :
                        
                        s=s[0:offset*2]
                        
                        nb_octet_lu=offset
                        


                    #Erreur : Trame incompléte
                    if offset > nb_octet_lu :
                        print(" La ligne ",nb_ligne," de la trame ",nb_trame, "est incomplet")
                        return
                debut_ligne+=1
            #pas debur de ligne
            else :
                #ignorer les octets qui ne sont pas sur 2 octets
                if len(octet) != 2 :
                    continue
                try:
                    n=int(octet,16)
                except:
                    #ignorer les lettre >f
                    continue
                s=s+octet
                nb_octet_lu+=1
                debut_ligne+=1
        nb_ligne+=1
    if s!="" :
        #ajouter la trame au dictionnaire
        liste_trame[nb_trame]=s
    #print(liste_trame)
    #print(len(liste_trame[0]))
    return liste_trame              
"""
Une fonction qui permet de lire un fichier à partir de son nom
:nom: le nom du fichier
"""
def lire_fichier(nom=''):
    if nom!='':
        try: 
            f=open(nom,"r")
            trame=f.readlines()
        except:
            print("le fichier : ",nom," n'existe pas")
            s=input("Entrer le nom du fichier : ")
            return lire_fichier(s)
        return trame
    nom = input("Entrer le nom du fichier : ")
    try:
        f=open(nom,"r")
    except:
        print("le fichier : ",nom," n'existe pas")
        return lire_fichier()
    trame=f.readlines()
    return trame
"""
Décoder la trame Ethernet
:trame: La trame à décoder
:return : un dictionnaire avec les champs de l'entete etheret
"""
def ethernet(trame):
    #champs
    dico = {"adr_destination":"","adr_source":"","type":""}
    cpt=0
    #Taille de entete de la trame ethernet : 14 octet (28 caracteres) 
    for cpt in range(28):
        #adr_destination
        if cpt < 12:
            if cpt == 11 or (cpt)%2==0:
                dico["adr_destination"]+=trame[cpt]
            else :
                dico["adr_destination"]+=trame[cpt]+":"
        #adr_source
        elif cpt < 24:
            if cpt == 23 or (cpt)%2==0:
                dico["adr_source"]+=trame[cpt]
            else :
                dico["adr_source"]+=trame[cpt]+":"
        #type
        elif cpt < 28:
            dico["type"]+=trame[cpt]

    return dico
"""
Une fonction qui renvoi le type de la trame ethernet
:dico: pour récuperer le champs type 
"""
def type_ethernet(dico):
    t=dico["type"]
    if t=="0800":
        return "IPv4"
    if t=="0805":
        return "X.25 niveau 3"
    if t=="0806":
        return "ARP"
    if t=="8035":
        return "RARP"
    if t=="8098":
        return "Appletalk"
"""
Une fonction qui prend en parametre une trame et rend les champs de l'entete IP
:trame: la trame à décoder
:return : les champs de l'entete IP
"""
def ip(trame):
    dico = {"Version":"","IHL":"","TOS":"","Total length":"","Identification":"","Flags":"","Fragment offset":"","TTL":"","Protocol":"","Header checksum":"","Source address":"","Destination address":""}
    i=28
    while(i<68):
        if i == 28 :
            dico["Version"]=trame[i]
        elif i==29 :
            dico["IHL"]=trame[i]
        elif i<32 :
            dico["TOS"]+=trame[i]
        elif i<36 :
            dico["Total length"]+=trame[i]
            
        elif i<40 :
            dico["Identification"]+=trame[i]
        elif i<41:
            f=int(trame[i],16)
            o=f %2
            if f==0:
                dico["Flags"]="000"
            if f==1:
                dico["Flags"]="001"
            if f==2:
                dico["Flags"]="010"
            if f==3:
                dico["Flags"]="011"
            if f>3 :
                f=bin(int(trame[i],16))[12:15]
                dico["Flags"]=f
        elif i<44 :
            dico["Fragment offset"]=str(f)
            if i%2 == 0 and i!=41 :
                dico["Fragment offset"]+=" "
            dico["Fragment offset"]+=trame[i]
        elif i<46 :
            dico["TTL"]+=trame[i]
        elif i<48 :
            dico["Protocol"]+=trame[i]
        
        elif i<52:
            if i%2 == 0 and i!=48:
                dico["Header checksum"]+=" "
            dico["Header checksum"]+=trame[i]
        elif i<60 :
            f=int(trame[i],16)
            f1=int(trame[i+1],16)
            if i != 52 or (i)%2!=0:
                dico["Source address"]+="."
            dico["Source address"]+=str(f*16+f1)
            i+=1
        elif i<68 and i+1<len(trame) :
            f=int(trame[i],16)
            f1=int(trame[i+1],16)
            if i != 60 or (i)%2!=0:
                dico["Destination address"]+="."
            dico["Destination address"]+=str(f*16+f1)
            i+=1
        i+=1
    option={}
    taille_ip=4*int(dico["IHL"],16)-20
    if taille_ip>0:
        type_opt= int(trame[68],16)*16 + int(trame[69],16)
        #Décoder quelques options IP
        if type_opt==7 :
            option={"Type":"7","Nom":"Record Route (RR)","Longeur":"","Pointeur":""}
            option["Longeur"]=trame[70]+trame[71]
            option["Pointeur"]=trame[72]+trame[73]

        elif type_opt==0:
            option={"Type":"0","Nom":"End of Options List"}
        elif type_opt==1:
            option={"Type":"1","Nom":"No Operation"}
        elif type_opt==68:
            option={"Type":"68","Nom":"Time Stamp (TS)"}
        elif type_opt==131:
            option={"Type":"131","Nom":"Loose Routing "}
        elif type_opt==137:
            option={"Type":"137","Nom":"Strict Routing"}   

    return (dico,option)
"""
Une fonction qui prend en parametre une trame et rend les champs de l'entete UDP
:trame: la trame à décoder
:return : les champs de l'entete UDP
"""
def udp(trame) :
    dico={"Source port number":"","Destination port number":"","Length":"","Checksum":""}
    ipv,v=ip(trame)
    if(ipv["Protocol"]=="11"):
        #taille de l'entet IP: IHL * 4
        taille_ip=4*int(ipv["IHL"],16)*2
        debut=taille_ip+28
        i=debut
        while(i<debut+16 and i+1<len(trame)) :
            if i<debut+4:
                dico["Source port number"]+=trame[i]
            elif i<debut+8 :
                dico["Destination port number"]+=trame[i]
            elif i<debut+12:
                dico["Length"]+=trame[i]
            else :
                dico["Checksum"]+=trame[i]
            i+=1
    return dico
"""
Une fonction qui prend un entier et renvoi sa valeur en binaire sous forme de chaine de caractére
n:l'entier à convertir
"""
def bin(n):
    """Convertit un nombre en binaire"""
    q = -1
    res = ""
    while q != 0:
        q = n // 2
        r = n % 2
        res = str(r) + res
        n = q
    while len(res)<16 :
        res="0"+res
    return res
"""
Une fonction qui prend un ointeur et une trame en parametre ,et retourne la valeur pointée
:pnt: Le pointeur 
:trame: La trame
:deb_dns: Le début de la trame( on utilise la foonction pour décoder DNS)
"""

def pointeur(pnt,trame,deb_dns):
    #ecrire le pointeur en binaire et enlever les deux premiers bits (qui désignent juste que c'est un pointeur)
    b=bin(int(pnt,16))
    b=b[2:]
    pos=int(b,2)*2
    #la position où il faut commencer la lecture
    debut=deb_dns+pos
    s=""    
    if (debut+1<len(trame)) and int(trame[debut],16)<12 :
        while ((debut+1<len(trame) and (trame[debut]+trame[debut+1])!='00') ):
            
            if (debut+3<len(trame)):
                #si c'est un pointeur
                if int(trame[debut],16)>11 :

                    poin=trame[debut]+trame[debut+1]+trame[debut+2]+trame[debut+3]
                    debut+=4
                    return s+ pointeur(poin,trame,deb_dns)
            #On remplace les caracteres qui ne font pas partie de la table ascii par un point
            if int(trame[debut]+trame[debut+1],16) <32:
                s+="."
            else :
                s+=chr(int(trame[debut]+trame[debut+1],16))
            debut+=2
        return s
    else :
        #si c'est une chaine de caractere
        if (debut+3<len(trame)):

            poin=trame[debut]+trame[debut+1]+trame[debut+2]+trame[debut+3]
            debut+=4
            return s+ pointeur(poin,trame,deb_dns)
    return s
"""
Une fonction qui prend une trame en parametre ,et retourne l'entet de DNS
:pnt: Le pointeur 
:trame: La trame
"""    
def dns(trame):
    ud=udp(trame)
    dico={}
    #Dictionnaire des différents champs DNS
    #Si le port destination est DNS    
    if ud["Destination port number"]=="0035" or ud["Source port number"]=="0035":
        dico={"Transaction ID":"0x","Flags":"","Questions":"","Answer RRs":"","Authority RRs":"","Additional RRs":"","Queries":{},"Answers":{},"Authoritative nameservers":{},"Additional records":{}}
        #On récupére l'entete ip pour calculer la position de commencement de DNS
        ipv,o=ip(trame)
        taille_ip=4*int(ipv["IHL"],16)*2
        debut=taille_ip+44
        #debut DNS
        i=debut
        debut_dns=i
        while(i<debut+24) :
            if i<debut+4 :
                dico["Transaction ID"]+=trame[i]
            elif i<debut+8 :
                dico["Flags"]+=trame[i]
            elif i<debut+12 :
                dico["Questions"]+=trame[i]
            elif i<debut+16 :
                dico["Answer RRs"]+=trame[i]
            elif i<debut+20 :
                dico["Authority RRs"]+=trame[i]
            elif i<debut+24:
                dico["Additional RRs"]+=trame[i]
            i+=1
        dico["Questions"]=str(int(dico["Questions"],16))
        dico["Answer RRs"]=str(int(dico["Answer RRs"],16))
        dico["Authority RRs"]=str(int(dico["Authority RRs"],16))
        dico["Additional RRs"]=str(int(dico["Additional RRs"],16))
        flag=bin(int(dico["Flags"],16))
        op=int(flag[1:5],16)
        s=str(op)
        #Traitement de flags DNS
        if op==0 :
            s+="  (Requête standard (Query))"
        elif op==1:
            s+="  (Requête inverse (IQuery))"
        elif op==2:
            s+="  (Statut du serveur (Status))"
        else:
            s+="  ( Réservé pour utilisation future)"

        if flag[0]=="0":
            dico_flags={"Reponse":"0 (requête)","Opcode":s,"Authoritative":flag[5:6],"Truncated":flag[6:7],"Recursion desired":flag[7:8],"Recursion available":flag[8:9],"Z":flag[9:10]}
        else :
            op=int(flag[10:14],16)
            st=str(op)
            if op==0 :
                st+="  (Pas d’erreur)"
            elif op==1:
                st+="  (Erreur de format dans la requête)"
            elif op==2:
                st+="  (Problème sur serveur)"
            elif op ==3:
                st+="  ( Le nom n’existe pas)"
            elif op ==4:
                st+="  ( Non implémenté)"
            elif op ==5:
                st+="  ( Refus)"
            else:
                st+="  ( Réservés)"
            dico_flags={"Reponse":"1 (reponse)","Opcode":s,"Authoritative":flag[5:6],"Truncated":flag[6:7],"Recursion desired":flag[7:8],"Recursion available":flag[8:9],"Z":flag[9:10],"Rcode ":st}
        #Dictionnaire pour les champs de la section Question
        dict_qs={"NAME":"","TYPE":"","CLASS":""}
        tmp=""
        #s'il y'a des question
        if dico["Questions"] != "0":
            #nombre de questions 
            nb_qst=int(dico["Questions"],16)
            #Pour chaque question :
            for v in range(nb_qst):
                #Lire la chaine de caractere jusq'uà trouver un caractere de fin de chaine (00)
                while (trame[i]+trame[i+1])!="00" :
                    if int(trame[i],16)>11 :
                        #Si c'est un pointeur, on appelle la fonction qui permet de retrouver le champs pointé 
                        dict_qs["NAME"]=pointeur(trame[i]+trame[i+1]+trame[i+2]+trame[i+3],trame,debut_dns)
                        i+=2
                    else :
                        #si ce n'est pas un pointeur,on lis la chaine de caractere
                        tmp=trame[i]+trame[i+1]
                        if int(tmp,16)<32 :
                            dict_qs["NAME"]+="."
                        else:
                            dict_qs["NAME"]+=chr(int(tmp,16))
                        tmp=""
                    i+=2
                dict_qs["NAME"]=dict_qs["NAME"][1:]
                dict_qs["NAME"]+= (" [Name Length :"+ str(len(dict_qs["NAME"])-1)+"]")
                s=""
                i+=2
                #récupérer le type de la question
                for g in range(i,i+4):
                    s+=trame[g]
                    
                s=int(s,16)
                #les différents types
                if s==1 :
                    dict_qs["TYPE"]="A ("+str(s)+")"
                elif s==28 :
                    dict_qs["TYPE"]="AAAA ("+str(s)+")"
                elif s==5 :
                    dict_qs["TYPE"]="CNAME ("+str(s)+")"
                elif s==2 :
                    dict_qs["TYPE"]="NS ("+str(s)+")"
                elif s==15 :
                    dict_qs["TYPE"]="MX ("+str(s)+")"
                elif s==16 :
                    dict_qs["TYPE"]="TXT ("+str(s)+")"
                else:
                    dict_qs["TYPE"]=" ("+str(s)+")"
                s=""
                #La classe de la question
                for g in range(i+4,i+8):
                    s+=trame[g]
                if s=="0001":
                    dict_qs["CLASS"]= "IN (0x"+s+")"
                
                dico["Queries"][v]=dict_qs
                i+=8
        
        tmp=""
        #verifier le nombre de réponse
        if dico["Answer RRs"] != "0": 
            nb_qst=int(dico["Answer RRs"],16)
            #pour chaque réponse
            for y in range(int(dico["Answer RRs"])):
                dict_rp={"NAME":"","TYPE":"","CLASS":"","TTL":"","Data length":""}
                while i+1<len(trame) and (trame[i]+trame[i+1]) !="00" :
                    
                    if int(trame[i],16)>11 :
                        
                        dict_rp["NAME"]+=pointeur(trame[i]+trame[i+1]+trame[i+2]+trame[i+3],trame,debut_dns)
                        
                        i+=2
                    
                    else :
                        tmp=trame[i]+trame[i+1]
                        if int(tmp,16)<32 :
                            dict_rp["NAME"]+="."
                        else:
                            dict_rp["NAME"]+=chr(int(tmp,16))
                        tmp=""
                    
                    i+=2
                
                dict_rp["NAME"]=dict_rp["NAME"][1:]
                dict_rp["NAME"]+= (" [Name Length :"+ str(len(dict_rp["NAME"])-1)+"]")
                s=""
                for g in range(i,i+4):
                    s+=trame[g]
                s=int(s,16)
                #le type                
                if s==1 :
                    dict_rp["TYPE"]="A ("+str(s)+")"
                elif s==28 :
                    dict_rp["TYPE"]="AAAA ("+str(s)+")"
                elif s==5 :
                    dict_rp["TYPE"]="CNAME ("+str(s)+")"
                elif s==2 :
                    dict_rp["TYPE"]="NS ("+str(s)+")"
                elif s==15 :
                    dict_rp["TYPE"]="MX ("+str(s)+")"
                elif s==16 :
                    dict_rp["TYPE"]="TXT ("+str(s)+")"
                else:
                    dict_rp["TYPE"]=" ("+str(s)+")"
                s=""
                #La classe de la réponse
                for g in range(i+4,i+8):
                    s+=trame[g]
                if s=="0001":
                    dict_rp["CLASS"]= "IN (0x"+s+")"
                i+=8
                #récuperer le TTL
                for h in range(i,i+8):
                    dict_rp["TTL"]+=trame[h]
                #Pour l'affihage en heure,minute et seconde
                s=str(relativedelta(seconds=int(dict_rp["TTL"],16)))
                dict_rp["TTL"]=str(int(dict_rp["TTL"],16))+" " +s[13:]
                i+=8
                #Data length
                for h in range(i,i+4):
                    dict_rp["Data length"]+=trame[h]
                dict_rp["Data length"]=str(int(dict_rp["Data length"],16))
                i+=4
                #les champs différent du type
                #Pour le type MX: 
                if dict_rp["TYPE"]=="MX (15)" :
                    dict_rp["Preference"]=""
                    dict_rp["Mail Exchange"]=""
                    for h in range(i,i+4):
                        dict_rp["Preference"]+=trame[h]
                    dict_rp["Preference"]=str(int(dict_rp["Preference"],16))
                    i+=4
                    max=int(dict_rp["Data length"])-2
                    while (trame[i]+trame[i+1]) !="00" and max>0 :
                    
                        if int(trame[i],16)>11 :
                            
                            dict_rp["Mail Exchange"]+=pointeur(trame[i]+trame[i+1]+trame[i+2]+trame[i+3],trame,debut_dns)
                            max=max-1
                            i+=2
                        else :
                            tmp=trame[i]+trame[i+1]
                            if int(tmp,16)<32 :
                                dict_rp["Mail Exchange"]+="."
                            else:
                                dict_rp["Mail Exchange"]+=chr(int(tmp,16))
                            tmp=""
                        max=max-1
                        
                        i+=2
                #Pour les types : A et AAAA
                if dict_rp["TYPE"]=="A (1)" or dict_rp["TYPE"]=="AAAA (28)" :
                    dict_rp["Adress"]=""
                    nb_addr=int(int(dict_rp["Data length"])/4)
                    for cpt in range(nb_addr):
                        for j in range(i+cpt*8,i+8+cpt*8):
                            if  (j)%2 and j+1<len(trame)==0:
                                f=int(trame[j],16)
                                f1=int(trame[j+1],16)
                                dict_rp["Adress"]+=str(f*16+f1)
                                if j<i+5 :
                                    dict_rp["Adress"]+="."
                                j-=1
                    i+=nb_addr*8
                #Pour les type: CNAME  et NS:
                if dict_rp["TYPE"]=="CNAME (5)" or dict_rp["TYPE"]=="NS (2)":
                    max=int(dict_rp["Data length"])
                    z=max*2+i

                    dict_rp["CNAME"]=""
                    while (trame[i]+trame[i+1]) !="00" and max>0 :
                        if int(trame[i],16)>11 :
                            
                            dict_rp["CNAME"]+=pointeur(trame[i]+trame[i+1]+trame[i+2]+trame[i+3],trame,debut_dns)
                            max=max-1
                            i+=2
                        else :
                            tmp=trame[i]+trame[i+1]
                            if int(tmp,16)<32 :
                                dict_rp["CNAME"]+="."
                            else:
                                dict_rp["CNAME"]+=chr(int(tmp,16))
                            tmp=""
                        max=max-1
                        i+=2
                    dict_rp["CNAME"]=dict_rp["CNAME"][1:]
                    i=z

                dico["Answers"][y]=dict_rp
        tmp=""
        #nombre de Authority 
        if dico["Authority RRs"] != "0": 
            nb_qst=int(dico["Authority RRs"],16)
            #Pour chaque authority
            for y in range(int(dico["Authority RRs"])):
                #Les champs de authority sous forme de dictionnaire
                dict_rp={"NAME":"","TYPE":"","CLASS":"","TTL":"","Data length":"","Name Server":""}
                p=""
                while (trame[i]+trame[i+1] !="00") :
                    #Si c'est un pointeur
                    if int(trame[i],16)>11 :
                        p+=pointeur(trame[i]+trame[i+1]+trame[i+2]+trame[i+3],trame,debut_dns)
                        i+=2
                    else :
                        tmp=trame[i]+trame[i+1]
                        if int(tmp,16)<32 :
                            p+="."
                        else:
                            p+=chr(int(tmp,16))
                        tmp=""
                    i+=2
                dict_rp["NAME"]=p[1:]
                s=""
                for g in range(i,i+4):
                    s+=trame[g]
                s=int(s,16)
                #Décoder les types
                if s==1 :
                    dict_rp["TYPE"]="A ("+str(s)+")"
                elif s==28 :
                    dict_rp["TYPE"]="AAAA ("+str(s)+")"
                elif s==5 :
                    dict_rp["TYPE"]="CNAME ("+str(s)+")"
                elif s==2 :
                    dict_rp["TYPE"]="NS ("+str(s)+")"
                elif s==15 :
                    dict_rp["TYPE"]="MX ("+str(s)+")"
                elif s==16 :
                    dict_rp["TYPE"]="TXT ("+str(s)+")"
                else:
                    dict_rp["TYPE"]=" ("+str(s)+")"
                s=""
                #La classe
                for g in range(i+4,i+8):
                    s+=trame[g]
                if s=="0001":
                    dict_rp["CLASS"]= "IN (0x"+s+")"
                i+=8
                #TTL
                for h in range(i,i+8):
                    dict_rp["TTL"]+=trame[h]
                s=str(relativedelta(seconds=int(dict_rp["TTL"],16)))
                dict_rp["TTL"]=str(int(dict_rp["TTL"],16))+" " +s[13:]
                i+=8
                #Data length
                for h in range(i,i+4):
                    dict_rp["Data length"]+=trame[h]
                dict_rp["Data length"]=str(int(dict_rp["Data length"],16))
                i+=4
                if dict_rp["TYPE"]=="CNAME (5)" or dict_rp["TYPE"]=="NS (2)":
                    max=int(dict_rp["Data length"])
                    #La prochaine adresse  
                    z=max*2+i
                    dict_rp["Name Server"]=""
                    while (trame[i]+trame[i+1]) !="00" and max>0 :
                        #si c'est un pointeur
                        if int(trame[i],16)>11 :
                            dict_rp["Name Server"]+=pointeur(trame[i]+trame[i+1]+trame[i+2]+trame[i+3],trame,debut_dns)
                            max=max-1
                            i+=2
                        else :
                            tmp=trame[i]+trame[i+1]
                            if int(tmp,16)<32 :
                                dict_rp["Name Server"]+="."
                            else:
                                dict_rp["Name Server"]+=chr(int(tmp,16))
                            tmp=""
                        max=max-1
                        i+=2
                    dict_rp["Name Server"]=dict_rp["Name Server"][1:]
                    i=z
                dico["Authoritative nameservers"][y]=dict_rp            
        tmp=""
        #Partie Additionnelle
        if dico["Additional RRs"] != "0": 
            nb_qst=int(dico["Additional RRs"],16)
            for y in range(int(dico["Additional RRs"])):
                #les champs de Additional sous forme de dictionnaire
                dict_rp={"NAME":"","TYPE":"","CLASS":"","TTL":"","Data length":"","Address":""}
                p=""
                while (trame[i]+trame[i+1] !="00") :
                    #Si c'est un pointeur
                    if int(trame[i],16)>11 :
                        p+=pointeur(trame[i]+trame[i+1]+trame[i+2]+trame[i+3],trame,debut_dns)
                        i+=2
                    else :
                        tmp=trame[i]+trame[i+1]
                        if int(tmp,16)<32 :
                            p+="."
                        else:
                            p+=chr(int(tmp,16))
                        tmp=""
                    i+=2
                dict_rp["NAME"]=p[1:]
                s=""
                for g in range(i,i+4):
                    s+=trame[g]
                #Type
                s=int(s,16)
                if s==1 :
                    dict_rp["TYPE"]="A ("+str(s)+")"
                elif s==28 :
                    dict_rp["TYPE"]="AAAA ("+str(s)+")"
                elif s==5 :
                    dict_rp["TYPE"]="CNAME ("+str(s)+")"
                elif s==2 :
                    dict_rp["TYPE"]="NS ("+str(s)+")"
                elif s==15 :
                    dict_rp["TYPE"]="MX ("+str(s)+")"
                elif s==16 :
                    dict_rp["TYPE"]="TXT ("+str(s)+")"
                else:
                    dict_rp["TYPE"]=" ("+str(s)+")"
                s=""
                #La classe
                for g in range(i+4,i+8):
                    s+=trame[g]
                if s=="0001":
                    dict_rp["CLASS"]= "IN (0x"+s+")"
                i+=8
                #TTL
                for h in range(i,i+8):
                    dict_rp["TTL"]+=trame[h]
                s=str(relativedelta(seconds=int(dict_rp["TTL"],16)))
                dict_rp["TTL"]=str(int(dict_rp["TTL"],16))+" " +s[13:]
                i+=8
                #Data length
                for h in range(i,i+4):
                    dict_rp["Data length"]+=trame[h]
                dict_rp["Data length"]=str(int(dict_rp["Data length"],16))
                i+=4
                #Type
                if dict_rp["TYPE"]=="A (1)":
                    max=int(dict_rp["Data length"])
                    z=max*2+i
                    #Nombre d'adresse  qu'elle contient
                    nb_addr=int(int(dict_rp["Data length"])/4)
                    for cpt in range(nb_addr):
                        #Récupérer l'adresse
                        for j in range(i+cpt*8,i+8+cpt*8):
                            if  (j)%2==0:
                                f=int(trame[j],16)
                                f1=int(trame[j+1],16)
                                dict_rp["Address"]+=str(f*16+f1)
                                if j<i+5 :
                                    dict_rp["Address"]+="."
                                j-=1
                    i+=nb_addr*8
                if dict_rp["TYPE"]=="AAAA (28)" :
                    #Adresse IPV6
                    max=int(dict_rp["Data length"])
                    z=max*2+i
                    nb_addr=int(int(dict_rp["Data length"])/16)
                    for cpt in range(nb_addr):
                        for j in range(i+cpt*32,i+32+cpt*32):
                            if  (j)%4==0:
                                f=int(trame[j],16)
                                f1=int(trame[j+1],16)
                                dict_rp["Address"]+=trame[j]+trame[j+1]+trame[j+2]+trame[j+3]
                                if j<i+27:
                                    dict_rp["Address"]+=":"
                                j-=1
                    i+=nb_addr*32
                dico["Additional records"][y]=dict_rp    
    return dico,dico_flags
"""
Une fonction qui prend une trame en parametre et renvoi l'entet  DHCP, les options de DHCP et son type
"""
def dhcp(trame):
    ud=udp(trame)
    dico={}
    dict_option={}
    #On verifie si c'est bien le protocole DHCP
    if ud["Destination port number"]=="0043" or ud["Source port number"]=="0043":
        #les champs de l'entete DHCP
        dico={"Message type":"","Hardware type":"","Hardware address length":"","Hops":"","Transaction ID":"","Seconds elapsed":"","Bootp flags":"",
        "Client IP address":"","Your (client) IP address":"","Next server IP address":"","Relay agent IP address":"","Client MAC address":"","Client hardware address padding":"","Server host name":"","Boot file name":"","Magic cookie":""}
        ipv,o=ip(trame)
        taille_ip=4*int(ipv["IHL"],16)*2
        debut=taille_ip+44
        #Le début de la trame DHCP
        i=debut
        s=""
        for j in range(i,i+2):
            s+=trame[j]
        #Type du message
        if s=="01" :
            dico["Message type"]="Boot Request (1)"
        if s=="02" :
            dico["Message type"]="Boot Reply (2)"
        i+=2
        s=""
        for j in range(i,i+2):
            s+=trame[j]
        if s=="01" :
            dico["Hardware type"]="Ethernet (0x01)"
        if s=="06" :
            dico["Hardware type"]="IEEE 802 (0x06)"
        i+=2
        s=""
        #Taille de l'adresse
        for j in range(i,i+2):
            s+=trame[j]
        dico["Hardware address length"]=str(int(s,16))
        i+=2
        s=""
        for j in range(i,i+2):
            s+=trame[j]
        dico["Hops"]=str(int(s,16))
        i+=2
        s=""
        for j in range(i,i+8):
            s+=trame[j]
        dico["Transaction ID"]="0x"+s
        i+=8
        s=""
        for j in range(i,i+4):
            s+=trame[j]
        dico["Seconds elapsed"]=str(int(s,16))
        i+=4
        s=""
        for j in range(i,i+4):
            s+=trame[j]
        dico["Bootp flags"]="0x"+s
        i+=4
        s=""
        #Client IP address
        for j in range(i,i+8):
            if  (j)%2==0:
                f=int(trame[j],16)
                f1=int(trame[j+1],16)
                dico["Client IP address"]+=str(f*16+f1)
                if j<i+5 :
                    dico["Client IP address"]+="."
                j-=1
        i+=8
        s=""
        #Client) IP address
        for j in range(i,i+8):
            if  (j)%2==0:
                f=int(trame[j],16)
                f1=int(trame[j+1],16)
                
                dico["Your (client) IP address"]+=str(f*16+f1)
                if j<i+5 :
                    dico["Your (client) IP address"]+="."
                j-=1
        i+=8
        for j in range(i,i+8):
            if  (j)%2==0:
                f=int(trame[j],16)
                f1=int(trame[j+1],16)
                
                dico["Next server IP address"]+=str(f*16+f1)
                if j<i+5 :
                    dico["Next server IP address"]+="."
                j-=1
        i+=8
        for j in range(i,i+8):
            if  (j)%2==0:
                f=int(trame[j],16)
                f1=int(trame[j+1],16)
                
                dico["Relay agent IP address"]+=str(f*16+f1)
                if j<i+5 :
                    dico["Relay agent IP address"]+="."
                j-=1
        i+=8
        for cpt in range(i,i+12):
            if i+cpt == 11 or (i+cpt)%2==0:
                dico["Client MAC address"]+=trame[cpt]
            else :
                dico["Client MAC address"]+=trame[cpt]+":"
        i+=12
        for j in range(i,i+20):
            dico["Client hardware address padding"]+=trame[j]
        i+=20
        for j in range(i,i+128):
            s+=trame[j]
        if int(s,16)==0 :
            dico["Server host name"]="not given"
        else : 
            dico["Server host name"]=s 
        i+=128
        for j in range(i,i+256):
            s+=trame[j]
        if int(s,16)==0 :
            dico["Boot file name"]="not given"
        else : 
            dico["Boot file name"]=s 
        i+=256
        s=""
        for j in range(i,i+8):
            s+=trame[j]
        if s=="63825363":
            dico["Magic cookie"]="DHCP"
        i+=8
        fin=False
        #Dictionnaire contenant toute les options
        dict_option={}
        dict_option["Option: (53) DHCP Message Type"]=""
        #Tant qu'on a pas trouvé l'option END
        while fin==False and i+1<len(trame) :
            f=int(trame[i],16)
            f1=int(trame[i+1],16)
            num_opt=f*16+ f1 
            i+=2
            if (num_opt == 255):
                dict_option["Option: (255) End"]= ""
                fin=True 
                break
            elif (num_opt== 53):
                leng=int(trame[i],16)*16 +int(trame[i+1],16)
                dict_option["Option: (53) DHCP Message Type"]=  ('\tLength :'+str(leng))+"\n"
                
                i+=2
                s=""
                type_dhcp=""
                for j in range(i,i+2*leng):
                    s+=trame[j]
                if int(s,16)==1 :
                    dict_option["Option: (53) DHCP Message Type"]+= "\t\t\tDHCP : Discover (1)"
                    type_dhcp="(Discover)"
                elif int(s,16)==2 :
                    dict_option["Option: (53) DHCP Message Type"]+= "\t\t\tDHCP : Offer (2)"
                    type_dhcp="(Offer)"
                elif int(s,16)==3 :
                    dict_option["Option: (53) DHCP Message Type"]+= "\t\t\tDHCP : Request (3)" 
                    type_dhcp="(Request)"
                elif int(s,16)==4 :
                    dict_option["Option: (53) DHCP Message Type"]+= "\t\t\tDHCP : Decline (4)"
                    type_dhcp="(Decline)"
                elif int(s,16)==5 :
                    dict_option["Option: (53) DHCP Message Type"]+= "\t\t\tDHCP : ACK (5)"
                    type_dhcp="(ACK)"
                elif int(s,16)==6 :
                    dict_option["Option: (53) DHCP Message Type"]+= "\t\t\tDHCP : NAK (6)"
                    type_dhcp="(NAK)"
                elif int(s,16)==7 :
                    dict_option["Option: (53) DHCP Message Type"]+= "\t\t\tDHCP : Release (7)"
                    type_dhcp="(Release)"
                elif int(s,16)==8 :
                    dict_option["Option: (53) DHCP Message Type"]+= "\tDHCP : Inform (8)"
                    type_dhcp="(Inform)"
                i+=2*leng
                s=""
            elif (num_opt == 51):
                leng=int(trame[i],16)*16 +int(trame[i+1],16)
                dict_option["Option: (51) IP Address Lease Time"]=  ('\tLength :'+str(leng))+"\n"
                i+=2
                s=""
                for j in range(i,i+2*leng):
                    s+=trame[j]
                h=str(relativedelta(seconds=int(s,16)))
                dict_option["Option: (51) IP Address Lease Time"]+="\t\t\tIP Address Lease Time: " +"("+str(int(s,16))+"s)"+h[13:]
                i+=2*leng
                s=""
            elif (num_opt== 58):
                leng=int(trame[i],16)*16 +int(trame[i+1],16)
                dict_option["Option: (58) Renewal Time Value"]=  ('\tLength :'+str(leng))+"\n"
                i+=2
                s=""
                for j in range(i,i+2*leng):
                    s+=trame[j]
                h=str(relativedelta(seconds=int(s,16)))
                dict_option["Option: (58) Renewal Time Value"]+="\t\t\tRenewal Time Value: " +"("+str(int(s,16))+"s)"+h[13:]
                i+=2*leng
                s=""
            elif (num_opt== 59):
                leng=int(trame[i],16)*16 +int(trame[i+1],16)
                dict_option["Option: (59) Rebinding Time Value"]=  ('\tLength :'+str(leng))+"\n"
                i+=2
                s=""
                for j in range(i,i+2*leng):
                    s+=trame[j]
                h=str(relativedelta(seconds=int(s,16)))
                dict_option["Option: (59) Rebinding Time Value"]+="\t\t\tRebinding Time Value: " +"("+str(int(s,16))+"s)"+h[13:]
                i+=2*leng
                s=""
            elif (num_opt== 54):
                leng=int(trame[i],16)*16 +int(trame[i+1],16)
                dict_option["Option: (54) DHCP Server Identification"]=  ('\tLength :'+str(leng))+"\n"
                i+=2
                s=""
                for j in range(i,i+2*leng):
                    if  (j)%2==0:
                        f2=int(trame[j],16)
                        f3=int(trame[j+1],16)
                        if j==i :
                            dict_option["Option: (54) DHCP Server Identification"]+="\t\t\tDHCP Server Identification :"
                        dict_option["Option: (54) DHCP Server Identification"]+=str(f2*16+f3)
                        if j !=(i+2*leng-2):
                            dict_option["Option: (54) DHCP Server Identification"]+="."
                    j-=1
                i+=2*leng   
                s=""
            elif (num_opt== 1):

                leng=int(trame[i],16)*16 +int(trame[i+1],16)
                dict_option["Option: (1) Subnet Mask"]=  ('\tLength :'+str(leng))+"\n"
                i+=2
                s=""
                for j in range(i,i+2*leng):
                    if  (j)%2==0 and j< len(trame):
                        f2=int(trame[j],16)
                        f3=int(trame[j+1],16)
                        if j==i :
                            dict_option["Option: (1) Subnet Mask"]+="\t\t\tSubnet Mask :"
                        dict_option["Option: (1) Subnet Mask"]+=str(f2*16+f3)
                        if j !=(i+2*leng-2):
                            dict_option["Option: (1) Subnet Mask"]+="."
                    j-=1
                i+=2*leng   
                s=""
            elif (num_opt== 50):
                leng=int(trame[i],16)*16 +int(trame[i+1],16)
                dict_option["Option: (50) Requested IP Address"]=  ('\tLength :'+str(leng))+"\n"
                i+=2
                s=""
                for j in range(i,i+2*leng):
                    if  (j)%2==0:
                        f2=int(trame[j],16)
                        f3=int(trame[j+1],16)
                        if j==i :
                            dict_option["Option: (50) Requested IP Address"]+="\t\t\tRequested IP Address :"
                        dict_option["Option: (50) Requested IP Address"]+=str(f2*16+f3)
                        if j !=(i+2*leng-2):
                            dict_option["Option: (50) Requested IP Address"]+="."
                    j-=1
                i+=2*leng   
                s=""
            elif (num_opt== 61):
                leng=int(trame[i],16)*16 +int(trame[i+1],16)
                dict_option["Option: (61) Client Identifier"]=  ('\tLength :'+str(leng))+"\n"
                i+=2
                
                s=""
                hard_type= trame[i]+trame[i+1]
                i+=2 
                if hard_type=='01':
                    dict_option["Option: (61) Client Identifier"]+="\t\t\tHardware type: Ethernet (0x01)"
                    nb_mac=(leng-1)/6
                    while (nb_mac > 0):
                        dict_option["Option: (61) Client Identifier"]+="\n\t\t\tClient MAC address : "
                        for cpt in range(12) :
                            if cpt == 11 or (cpt)%2==0:
                                dict_option["Option: (61) Client Identifier"]+=trame[i+cpt]
                            else :
                                dict_option["Option: (61) Client Identifier"]+=trame[i+cpt]+":"
                        nb_mac=nb_mac-1
                        i+=12
                else :
                    dict_option["Option: (61) Client Identifier"]+="\t\t\tHardware type: Inconnu"
                    i=i+leng*2-2
                
                s=""
            elif (num_opt==55) :
                leng=int(trame[i],16)*16 +int(trame[i+1],16)
                dict_option["Option: (55) Parameter Request List"]=  ('\tLength :'+str(leng))
                i+=2
                for j in range(leng):
         
                    s=trame[i+j*2]+trame[i+j*2+1]    
                    nume=int(s,16)
                    dict_option["Option: (55) Parameter Request List"]+="\n\t\t\tParameter Request List Item : " + "("+ str(nume) + ") "
                    if nume== 1 :
                        dict_option["Option: (55) Parameter Request List"]+= "Subnet Mask"
                    elif nume== 3 :
                        dict_option["Option: (55) Parameter Request List"]+= "Router"
                    elif nume== 6 :
                        dict_option["Option: (55) Parameter Request List"]+= "Domaine Name Server"
                    elif nume== 42 :
                        dict_option["Option: (55) Parameter Request List"]+= "Network Time Protocol Servers"
                    
                i+=2*leng
            elif (num_opt==3):
                leng=int(trame[i],16)*16 +int(trame[i+1],16)
                dict_option["Option: (3) Router"]=  ('\tLength :'+str(leng))+"\n"
                i+=2
                s=""
                for cpt in range (int(leng/4)):
                    for j in range(i+8*cpt,i+2*leng+cpt*8):
                        if  (j)%2==0:
                            f2=int(trame[j],16)
                            f3=int(trame[j+1],16)
                            if j==i :
                                dict_option["Option: (3) Router"]+="\tRouter : "
                            dict_option["Option: (3) Router"]+=str(f2*16+f3)
                            if j !=(i+2*leng-2):
                                dict_option["Option: (3) Router"]+="."
                        j-=1
                i+=2*leng   
                s=""

            else :
                leng=int(trame[i],16)*16 +int(trame[i+1],16)
                dict_option["Option: ("+ str(num_opt) +")"]=('\tLength :'+str(leng))+"\n"
                i+=2*leng +2        
    return dico,dict_option,type_dhcp