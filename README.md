# Analyseur de trame réseau
   ## Présentation de l'analyseur :

<p>	 L’objectif de ce projet est de programmer un analyseur de protocoles réseau
	 ‘offline’. Il prend en entrée un fichier trace contenant les octets capturés
	 sur un réseau Ethernet. le programme s’exécuter dans une
	 fenêtre de commande (de type terminal). </p>

   ## Fonctionnalités :
   <ol>
	<li><strong> L'analyseur est  en mesure de décoder les couches suivantes: </strong></li>
	<ul>
	<li> Couche 2 : Ethernet</li>
	<li>Couche 3 : IP</li>
	<li>Couche 4 : UDP</li>
	<li>Couche 7 : DNS et DHCP</li>
	</ul>
    <li><strong> A chaque exécution, le résultat de l'analyseur est sauvegardé dans un
	    ficher texte formaté sous le nom de "Analyseur.txt" </strong></li>

  <strong><li> L'analyseur prend en entrée un fichier trace (format texte) contenant des octets
	   bruts, ce fichier pourra contenir plusieurs
		trames Ethernet à la suite (sans préambule ni champ FCS) </strong></li>

   ## Structure de l'analyseur :

<strong> Le programme est divisé en 2 fichiers :</strong>
		
	<li><p> <strong> reseau.py</strong> : L'ensemble des fonction est codé dans ce fichier :</p></li>
	<ul>
		<li><strong>lire_fichier :</strong> Permet de lire un fichier à partir de son nom</li>		
	        <li><strong> trame_to_ligne :</strong> Convertit un fichier de trames en un dictionnaire de chaine de caractére </li>				
		<li><strong>ethernet , type_ethernet :</strong> Décode la trame Ethernet et renvoi un dictionnaire contenant ses différents champs</li>
		<li><strong>ip :</strong> Prend en parametre une trame et renvoi un dictionnaire contenant les différents champs de l'entete  IP</li>
		<li><strong>udp : </strong>Prend en parametre une trame et rend les champs de l'entete UDP</li>
		<li><strong>bin :</strong> Prend un entier et renvoi sa valeur en binaire sous forme de chaine de caractéres</li>
		<li><strong>pointeur :</strong> Prend un pointeur et une trame en parametre ,et retourne la valeur du champs pointé (fonction récursive)</li>
		<li><strong>dns :</strong> Prend une trame en parametre ,et renvoi un dictionnaire contenant les différents champs de DNS</li>
		<li><strong>dhcp :</strong> Prend une trame en parametre ,et renvoi un dictionnaire contenant les différents champs de DHCP</li>
	</ul>

	<li><p> <strong> main.py </strong>: permet de </p></li>

		<ul> 
			<li>Faire appel aux fonctions précédentes</li>	
			<li>Enregistre le résultat renvoyé dans un fichier nommé " "Analyseur.txt" pour faciliter la lecture</li>
		</ul>

   ## Langage de programmation :
   <p><strong>Python </strong></p>

   ## Auteurs :
   <p><strong>Koceila KEMICHE - Ghiles OUHENIA</strong></p>
	
