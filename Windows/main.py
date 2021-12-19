# -*- coding: utf-8 -*-

import numpy as np
import random
import matplotlib 
import csv
import reseau
from dateutil.relativedelta import relativedelta
def if_set(n):
    if n==0 :
        return "Not set"
    else :
        return "Set"
def is_not(n):
    if n=="0" :
        return "is not"
    else :
        return "is"
if __name__=='__main__':
    
    trame=reseau.lire_fichier()
    dico_trame=reseau.trame_to_ligne(trame)
    
    
    fichier=open("Analyseur.txt","w")
    
    if dico_trame!=None:
        for m in dico_trame:
            print()
            ethernet = reseau.ethernet(dico_trame[m])
            type_eth=reseau.type_ethernet(ethernet)
            fichier.write("\n")
            print("Frame "+str(m)+": "+ str(int(len(dico_trame[m])/2))+" bytes on wire ("+str(8*int(len(dico_trame[m])/2))+" bits), "+ str(int(len(dico_trame[m])/2))+" bytes captured ("+str(8*int(len(dico_trame[m])/2))+" bits)")

            fichier.write("Frame "+str(m)+": "+ str(int(len(dico_trame[m])/2))+" bytes on wire ("+str(8*int(len(dico_trame[m])/2))+" bits), "+ str(int(len(dico_trame[m])/2))+" bytes captured ("+str(8*int(len(dico_trame[m])/2))+" bits)\n")
            print()
            fichier.write("\n")
            print("\tEthernet II, Src: ("+ ethernet["adr_source"]+"), Dst: (" + ethernet["adr_destination"]+")")
            fichier.write("\tEthernet II, Src: ("+ ethernet["adr_source"]+"), Dst: (" + ethernet["adr_destination"]+")\n")

            print("\t\tDestination : (" + ethernet["adr_destination"]+")")
            fichier.write("\t\tDestination : (" + ethernet["adr_destination"]+")\n")

            print("\t\tSource : (" + ethernet["adr_source"]+")")
            fichier.write("\t\tSource : (" + ethernet["adr_source"]+")\n")
            
            print("\t\tType : " + type_eth+" (0x"+ethernet["type"]+")")
            fichier.write("\t\tType : " + type_eth+" (0x"+ethernet["type"]+")\n")
            
            
            print()
            fichier.write("\n")
            if ethernet["type"]=="0800":
                ip,opt=reseau.ip(dico_trame[m])
                print("\tInternet Protocol Version 4, Src: ("+ ip["Source address"]+"), Dst: (" + ip["Destination address"]+")")
                fichier.write("\tInternet Protocol Version 4, Src: ("+ ip["Source address"]+"), Dst: (" + ip["Destination address"]+")\n")
                
                s=reseau.bin(4)
                s=s[12:]
                print("\t\t"+s+" .... = Version : "+ip["Version"])
                fichier.write("\t\t"+s+" .... = Version : "+ip["Version"]+" \n")
                s=""
                s=reseau.bin(int(ip["IHL"],16))
                s=s[12:]

                print("\t\t ...."+s+" = Header Length : "+str(int(ip["IHL"],16)*4))
                fichier.write("\t\t ...."+s+ " = Header Length : "+ str(int(ip["IHL"],16)*4)+ " \n")
                s=""
                print("\t\tDifferentiated Services Field :0x"+ip["TOS"])
                fichier.write("\t\tDifferentiated Services Field :0x"+ip["TOS"]+ " \n")

                print("\t\tTotal Length :"+str(int(ip["Total length"],16)))
                fichier.write("\t\tTotal Length :"+str(int(ip["Total length"],16))+ " \n")

                print("\t\tIdentification :0x"+ip["Identification"])
                fichier.write("\t\tIdentification :0x"+ip["Identification"]+ " \n")

                print("\t\tFlags: 0b"+ip["Flags"])
                fichier.write("\t\tFlags: 0b"+ip["Flags"]+ " \n")

                s=ip["Flags"]
                print("\t\t\t\t"+s[0]+"... .... = Reserved bit :"+if_set(int(s[0],16)))
                fichier.write("\t\t\t\t"+s[0]+"... .... = Reserved bit :"+if_set(int(s[0],16))+ " \n")

                print("\t\t\t\t"+"."+s[1]+"... .... = Don't fragment :"+if_set(int(s[0],16)))
                fichier.write("\t\t\t\t"+"."+s[1]+"... .... = Don't fragment  :"+if_set(int(s[0],16))+ " \n")

                print("\t\t\t\t"+".."+s[2]+"... .... = More fragment  :"+if_set(int(s[0],16)))
                fichier.write("\t\t\t\t"+".."+s[2]+"... .... = More fragment  :"+if_set(int(s[0],16))+ " \n")
                s=reseau.bin(int(ip["Flags"],16))
                s2=s[3:]
                print("\t\t\t\t"+"..."+s2+" = Fragment offset:"+ str(int(s[3:],2)))
                fichier.write("\t\t\t\t"+"..."+s2+" = Fragment offset:"+ str(int(s[3:],2))+ " \n")

                print("\t\tTime to Live:"+str(int(ip["TTL"],16)))
                fichier.write("\t\tTime to Live :"+str(int(ip["TTL"],16))+ " \n")

                

                s=""
                s2=""
                s=ip["Protocol"]
                if s=="11":
                    s2="UDP (17)"
                elif s=="06":
                    s2= "TCP (6)"

                print("\t\tProtocol:"+s2)
                fichier.write("\t\tProtocol:"+s2+ " \n")
                print("\t\tHeader Checksum: 0x"+ip["Header checksum"]+" [Unverified]")
                fichier.write("\t\tHeader Checksum: 0x"+ip["Header checksum"]+" [Unverified]\n")

                print("\t\tSource address: "+ip["Source address"])
                fichier.write("\t\tSource address: 0x"+ip["Source address"]+"\n")
                print("\t\tDestination address: "+ip["Destination address"])
                fichier.write("\t\tDestination address: "+ip["Destination address"]+"\n")
                if int(ip["IHL"],16)*4 >20:
                    print("\t\tOptions: "+opt["Type"])
                    fichier.write("\t\tOptions: "+opt["Type"]+"\n")
                    for c in opt.keys():
                        print("\t\t\t"+c+": "+opt[c])
                        fichier.write("\t\t\t"+c+": "+opt[c]+"\n")

                if(ip["Protocol"]=="11"):
                    udp=reseau.udp(dico_trame[m])
                    print()
                    fichier.write("\n")
                    print("\tUser Datagram Protocol, Src Port: "+ str(int(udp["Source port number"],16))+", Dst Port: " + str(int(udp["Destination port number"],16)))
                    fichier.write("\tUser Datagram Protocol, Src Port: "+ str(int(udp["Source port number"],16))+", Dst Port: " + str(int(udp["Destination port number"],16))+"\n")
                    print("\t\tSource Port: " + str(int(udp["Source port number"],16)))
                    fichier.write("\t\tSource Port: " + str(int(udp["Source port number"],16))+"\n")
                    print("\t\tDestination Port: " + str(int(udp["Destination port number"],16)))
                    fichier.write("\t\tDestination Port: " + str(int(udp["Destination port number"],16))+"\n")
                    print("\t\tLength: " + str(int(udp["Length"],16)))
                    fichier.write("\t\tLength: " + str(int(udp["Length"],16))+"\n")
                    print("\t\tChecksum: 0x" +udp["Checksum"]+" [unverified]")
                    fichier.write("\t\tChecksum: 0x" + udp["Checksum"]+" [unverified]"+"\n")
                    
                    print()
                    fichier.write("\n")
                    if udp["Destination port number"]=="0043" or udp["Source port number"]=="0043":
                        dhcp,opt,type_dhcp=reseau.dhcp(dico_trame[m])
                        print("\tDynamic Host Configuration Protocol :"+type_dhcp) 
                        fichier.write("\tDynamic Host Configuration Protocol: "+type_dhcp +" \n")
                        print("\t\tMessage type: " +dhcp["Message type"])
                        fichier.write("\t\tMessage type: " +dhcp["Message type"]+"\n")
                        print("\t\tHardware type: " +dhcp["Hardware type"])
                        fichier.write("\t\tHardware type: " +dhcp["Hardware type"]+"\n")
                        print("\t\tHardware address length: " +dhcp["Hardware address length"])
                        fichier.write("\t\tHardware address length: " +dhcp["Hardware address length"]+"\n")
                        print("\t\tHops: " +dhcp["Hops"])
                        fichier.write("\t\tHops: " +dhcp["Hops"]+"\n")
                        print("\t\tTransaction ID: " +dhcp["Transaction ID"])
                        fichier.write("\t\tTransaction ID: " +dhcp["Transaction ID"]+"\n")
                        print("\t\tSeconds elapsed: " +dhcp["Seconds elapsed"])
                        fichier.write("\t\tSeconds elapsed: " +dhcp["Seconds elapsed"]+"\n")
                        b=reseau.bin(int(dhcp["Bootp flags"][2:],16))
                        g=""
                        if b[0]=='0':
                            g="Unicast"
                            r=dhcp["Bootp flags"]
                        else:
                            g="Broadcast"
                            y=hex(int(b[1:],2))
                            r="0x"+y

                        print("\t\tBootp flags: " +dhcp["Bootp flags"]+' ('+ g+')')
                        fichier.write("\t\tBootp flags: " +dhcp["Bootp flags"]+"\n")
                        print("\t\t\t\t"+b[0]+"... .... .... .... = Broadcast flag: " +g)
                        fichier.write("\t\t\t\t"+b[0]+"... .... .... .... = Broadcast flag: " +g+"\n")
                        print("\t\t\t\t."+b[1:]+" = Reserved flag: " +dhcp["Bootp flags"])
                        fichier.write("\t\t\t\t"+b[0]+"... .... .... .... = Broadcast flag: " +r+"\n")
                        print("\t\tClient IP address: " +dhcp["Client IP address"])
                        fichier.write("\t\tClient IP address: " +dhcp["Client IP address"]+"\n")

                        print("\t\tYour (client) IP address: " +dhcp["Your (client) IP address"])
                        fichier.write("\t\tYour (client) IP address: " +dhcp["Your (client) IP address"]+"\n")
                        
                        print("\t\tNext server IP address: " +dhcp["Next server IP address"])
                        fichier.write("\t\tNext server IP address: " +dhcp["Next server IP address"]+"\n")
                        print("\t\tRelay agent IP address: " +dhcp["Relay agent IP address"])
                        fichier.write("\t\tRelay agent IP address: " +dhcp["Relay agent IP address"]+"\n")
                        print("\t\tClient MAC address: (" +dhcp["Client MAC address"]+")")
                        fichier.write("\t\tClient MAC address: (" +dhcp["Client MAC address"]+")\n")
                        print("\t\tClient hardware address padding: " +dhcp["Client hardware address padding"])
                        fichier.write("\t\tClient hardware address padding: " +dhcp["Client hardware address padding"]+"\n")
                        print("\t\tServer host name: " +dhcp["Server host name"])
                        fichier.write("\t\tServer host name: " +dhcp["Server host name"]+"\n")
                        print("\t\tBoot file name: " +dhcp["Boot file name"])
                        fichier.write("\t\tBoot file name: " +dhcp["Boot file name"]+"\n")
                        print("\t\tMagic cookie: " +dhcp["Magic cookie"])
                        fichier.write("\t\tMagic cookie: " +dhcp["Magic cookie"]+"\n")
                        
                        for c in opt.keys():
                            print()
                            fichier.write("\n")
                            print("\t\t"+c)
                            fichier.write("\t\t"+c+"\n")
                            print("\t\t"+opt[c])
                            fichier.write("\t\t"+opt[c]+"\n")

                    if udp["Destination port number"]=="0035" or udp["Source port number"]=="0035":
                        dns,flag=reseau.dns(dico_trame[0])
                        print("\tDomain Name System "+flag["Reponse"])
                        fichier.write("\tDomain Name System"+flag["Reponse"]+"\n")
                        print("\t\tTransaction ID: " +dns["Transaction ID"])
                        fichier.write("\t\tTransaction ID: " +dns["Transaction ID"]+"\n")
                        print("\t\tFlags: 0x" +dns["Flags"])
                        fichier.write("\t\tFlags: 0x" +dns["Flags"]+"\n")
                        b=reseau.bin(int(dns["Flags"],16))
                        print("\t\t\t\t"+b[0]+"... .... .... .... =  Response: Message is a"+flag["Reponse"])
                        fichier.write("\t\t\t\t"+b[0]+"... .... .... .... =  Response: Message is a"+flag["Reponse"]+"\n")
                        print("\t\t\t\t."+b[1:5]+"... .... .... =  Opcode: "+flag["Opcode"])
                        fichier.write("\t\t\t\t."+b[1:5]+"... .... .... =  Opcode: "+flag["Opcode"]+"\n")
                        print("\t\t\t\t.... ."+b[5]+".. .... .... =  Authoritative nameservers: Server "+is_not(b[5])+" an anthority for domain")
                        fichier.write("\t\t\t\t.... ."+b[5]+".. .... .... =  Authoritative nameservers: Server "+is_not(b[5])+" an anthority for domain\n")
                        print("\t\t\t\t.... .."+b[6]+". .... .... =  Truncated: Message "+is_not(b[6])+" truncated")
                        fichier.write("\t\t\t\t.... .."+b[6]+". .... .... =  Truncated: Message "+is_not(b[6])+" truncated\n")
                        print("\t\t\t\t.... ..."+b[7]+" .... .... =  Recursion "+is_not(b[7])+" desired")
                        fichier.write("\t\t\t\t.... ..."+b[7]+" .... .... =  Recursion "+is_not(b[7])+" desired\n")
                        print("\t\t\t\t.... .... "+b[8]+"... .... =  Recursion "+is_not(b[8])+" available")
                        fichier.write("\t\t\t\t.... .... "+b[8]+"... .... =  Recursion "+is_not(b[8])+" available\n")
                        print("\t\t\t\t.... .... ."+b[9]+". .... =  Z: reserved ("+str(b[9])+")")
                        fichier.write("\t\t\t\t.... .... ."+b[9]+".. .... =  Z: reserved ("+str(b[9])+")\n")
                        print("\t\t\t\t.... .... .."+b[10]+". .... =  Answer authenticated: Answer/authority portion "+str(b[10])+" authentic")
                        fichier.write("\t\t\t\t.... .... .."+b[10]+". .... =  Answer authenticated: Answer/authority portion "+str(b[10])+" authentic\n")
                        print("\t\t\t\t.... .... ..."+b[11]+" .... =  authenticated data: "+is_not(b[11])+" acceptable")
                        fichier.write("\t\t\t\t.... .... ..."+b[11]+" .... =  authenticated data: "+is_not(b[11])+" acceptable\n")
                        print("\t\t\t\t.... .... .... "+b[12:]+" =  Reply code: ("+str(int(b[12:],2))+")")
                        fichier.write("\t\t\t\t.... .... .... "+b[12:]+" =  Reply code: ("+str(int(b[12:],2))+")\n")

                        print("\t\tQuestions: " +dns["Questions"])
                        fichier.write("\t\tQuestions: " +dns["Questions"]+"\n")
                        print("\t\tAnswer RRs: " +dns["Answer RRs"])
                        fichier.write("\t\tAnswer RRs: " +dns["Answer RRs"]+"\n")
                        print("\t\tAuthority RRs: " +dns["Authority RRs"])
                        fichier.write("\t\tAuthority RRs: " +dns["Authority RRs"]+"\n")
                        print("\t\tAdditional RRs: " +dns["Additional RRs"])
                        fichier.write("\t\tAdditional RRs: " +dns["Additional RRs"]+"\n")
                        
                        q=dns["Queries"]
                        print("\t\tQueries")
                        fichier.write("\t\tQueries " "\n")
                        if len(q)>0:
                            for dic in q:
                                if dic > 0:
                                    print("\t\t\t\t\t\t------")
                                    fichier.write("\t\t\t\t\t\t------\n")
                                for c in q[dic].keys():
                                    print("\t\t\t\t"+c+": "+q[dic][c])
                                    fichier.write("\t\t\t\t"+c+": "+q[dic][c]+"\n")
                            
                        q=dns["Answers"]
                        print()
                        fichier.write("\n")
                        print("\t\tAnswers")
                        fichier.write("\t\tAnswers " "\n")
                        if len(q)>0:
                            for dic in q:
                                if dic > 0:
                                    print("\t\t\t\t\t\t------")
                                    fichier.write("\t\t\t\t\t\t------\n")
                                for c in q[dic].keys():
                                    print("\t\t\t\t"+c+": "+q[dic][c])
                                    fichier.write("\t\t\t\t"+c+": "+q[dic][c]+"\n")
                        
                        q=dns["Authoritative nameservers"]
                        print()
                        fichier.write("\n")
                        print("\t\tAuthoritative nameservers")
                        fichier.write("\t\tAuthoritative nameservers " "\n")
                        if len(q)>0:
                            for dic in q:
                                if dic > 0:
                                    print("\t\t\t\t\t\t------")
                                    fichier.write("\t\t\t\t\t\t------\n")
                                for c in q[dic].keys():
                                    print("\t\t\t\t"+c+": "+q[dic][c])
                                    fichier.write("\t\t\t\t"+c+": "+q[dic][c]+"\n")
                        
                        q=dns["Additional records"]
                        print()
                        fichier.write("\n")
                        print("\t\tAdditional records")
                        fichier.write("\t\tAdditional records " "\n")
                        if len(q)>0:
                            for dic in q:
                                if dic > 0:
                                    print("\t\t\t\t\t\t------")
                                    fichier.write("\t\t\t\t\t\t------\n")
                                for c in q[dic].keys():
                                    print("\t\t\t\t"+c+": "+q[dic][c])
                                    fichier.write("\t\t\t\t"+c+": "+q[dic][c]+"\n")

    #dhcp,opt=reseau.dhcp(dico_trame[0])
    fichier.close()