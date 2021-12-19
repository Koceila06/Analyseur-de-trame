# Analyseur de trame réseau
   ## Présentation de l'analyseur :

	 L’objectif de ce projet est de programmer un analyseur de protocoles réseau
	 ‘offline’. Il prend en entrée un fichier trace contenant les octets capturés
	 sur un réseau Ethernet. le programme s’exécuter dans une
	 fenêtre de commande (de type terminal).

   ## Fonctionnalités :
   <strong>L'analyseur est  en mesure de décoder les couches suivantes:</strong>
<ol>
	<ul>
	<li> Couche 2 : Ethernet</li>
	<li>Couche 3 : IP</li>
	<li>Couche 4 : UDP</li>
	<li>Couche 7 : DNS et DHCP</li>
	</ul>
   <strong> A chaque exécution, le résultat de l'analyseur est sauvegardé dans un
		ficher texte formaté sous le nom de "Analyseur.txt"</strong>

	<strong>L'analyseur prend en entrée un fichier trace (format texte) contenant des octets
	   bruts.  Ce fichier pourra contenir plusieurs
		trames Ethernet à la suite (sans préambule ni champ FCS)</strong>
# Analyseur de trame réseau
   ## Structure de l'analyseur :

		Le programme est divisé en 2 fichiers :
			->  reseau.py = L'ensemble des fonction est codé dans ce fichier
			-> main.py : Pour tester les  fonctions de reseau.py
		# reseau.py : contient 10 fonctions :

				-> lire_fichier : Une fonction qui permet de lire un fichier à partir de son nom
				
			        -> trame_to_ligne: Une fonction qui  convertit un fichier de trames en un dictionnaire de chaine de caractére 
				
				-> ethernet , type_ethernet : Décode la trame Ethernet et renvoi un dictionnaire contenant ses différents champs
				
				-> ip : Une fonction qui prend en parametre une trame et renvoi un dictionnaire contenant les différents champs de l'entete  IP

				-> udp :Une fonction qui prend en parametre une trame et rend les champs de l'entete UDP

				-> bin : Une fonction qui prend un entier et renvoi sa valeur en binaire sous forme de chaine de caractéres

				-> pointeur : Une fonction qui prend un pointeur et une trame en parametre ,et retourne la valeur du champs pointé (fonction récursive)

				-> dns :Une fonction qui prend une trame en parametre ,et renvoi un dictionnaire contenant les différents champs de DNS

				-> dhcp : :Une fonction qui prend une trame en parametre ,et renvoi un dictionnaire contenant les différents champs de DHCP
		# main.py : permet de :

				->  Faire appel aux fonctions précédentes
	
				-> Enregistre le résultat renvoyé dans un fichier nommé " "Analyseur.txt" pour faciliter la lecture

   Langage de programmation : Python 

   Auteurs : Koceila KEMICHE - Ghiles OUHENIA
	
