#!/usr/bin/env python
# -*- coding: utf-8 -*-

################################################################################################################################################
################################################################################################################################################

#le script accepte en paramètre le fichier à déchiffrer.
#le script lance ensuite hashcat avec une attaque par dictionnaire avec plusieurs dico =>
#un dico ville
#un dico prenom
#un dico nom de famille
#une fois que ces attaques ont été lancées,
#on passe à une attaque hybride basée sur les règles (rule based) sur les dictionnaires précédemment utilisés.
#je veux les transformations suivantes
#le mot avec la première lettre en majuscule
#le mot avec une lettre majuscule sur deux
#le mot avec un nombre de 4 chiffres à la fin
#le mot avec une majuscule au début et à la fin
#pendant que le script est lancé, il doit y avoir le moins
#d'output possible (tu verra que hashcat est très verbeux lorsqu'il est lancé). à toi de trouver un moyen de réduire à l'essentiel.

#c'est la version alpha 0.1.
#L'idée finale, c'est de créer un outil capable d'évaluer le respect des bonnes pratiques sur les mots de passe
#en te donnant le nombre de personne ayant choisi un nom, un prénom ou une ville comme pass,
#combien de personnes ont un mot de passe de moins de 6 caractères, etc...
#ensuite tu peux dresser des stats
################################################################################################################################################
################################################################################################################################################

#Librairies à importer
import sys
import os
from subprocess import call
os.system('clear')


#Message info au début du programme
print "Utilisation du script :"
print ""
print "0 = MD5, 10 = md5($pass.$salt), 20 = md5($salt.$pass), 50 = HMAC-MD5 (key = $pass)"
print "60 = HMAC-MD5 (key = $salt), 100 = SHA1, 110 = sha1($pass.$salt), 120 = sha1($salt.$pass)"
print "150 = HMAC-SHA1 (key = $pass), 160 = HMAC-SHA1 (key = $salt), 200 = MySQL, 300 = MySQL4.1/MySQL5"
print "400 = phpass, MD5(Wordpress), MD5(phpBB3),500 = md5crypt, MD5(Unix), FreeBSD MD5, Cisco-IOS MD5"
print "800 = SHA-1(Django), 900 = MD4, 1000 = NTLM"
print "101 = nsldap, SHA-1(Base64), Netscape LDAP SHa, d,111 = nsldaps, SSHA-1(Base64), Netscape LDAP SSHA"
print "121 = SMF > v1.1, 122 = OS X v10.4, v10.5, v10.6, 131 = MSSQL, 141 = EPiServer 6.x,1722 = OS X v10.7"
print "1731 = MSSQL 2012, 2611 = vBulletin < v3.8.5, 2711 = vBulletin > v3.8.5, 2811 = IPB2+, MyBB1.2+"
print "3721 = WebEdition CMS, 2500 = WPA2"
print "\n"
print "\n"


#Liste des masques possible à tester
masks = ["?d?d?d?d",
"?d?d?d?d?d?d",
"?d?d?d?d?d?d?d",
"?d?d?d?d?d?d?d?d",
"?d?d?d?d?d?d?d?d?d",
"?d?d?d?d?d?d?d?d?d?d",
"?d?d?d?d?l?l?l?l",
"?d?d?d?l?l?l?l",
"?d?d?d?l?l?l?l?l",
"?d?d?d?l?l?l?l?l?l",
"?d?d?l?l?l?l",
"?d?d?l?l?l?l?l",
"?d?d?l?l?l?l?l?l",
"?d?d?l?l?l?l?l?l?l",
"?d?l?l?l?l",
"?d?l?l?l?l?l",
"?d?l?l?l?l?l?l",
"?d?l?l?l?l?l?l?l",
"?d?l?l?l?l?l?l?l?l",
"?l?l?l?l",
"?l?l?l?l?d",
"?l?l?l?l?d?d",
"?l?l?l?l?d?d?d",
"?l?l?l?l?d?d?d?d",
"?l?l?l?l?d?s",
"?l?l?l?l?l",
"?l?l?l?l?l?d",
"?l?l?l?l?l?d?d",
"?l?l?l?l?l?d?d?d",
"?l?l?l?l?l?l",
"?l?l?l?l?l?l?d",
"?l?l?l?l?l?l?d?d",
"?l?l?l?l?l?l?d?d?d",
"?l?l?l?l?l?l?l",
"?l?l?l?l?l?l?l?d",
"?l?l?l?l?l?l?l?d?d",
"?l?l?l?l?l?l?l?l",
"?l?l?l?l?l?l?l?l?l",
"?l?l?l?l?l?l?l?l?d",
"?l?l?l?l?l?l?l?l?s",
"?l?l?l?l?l?l?l?s",
"?l?l?l?l?l?l?s",
"?l?l?l?l?l?s",
"?l?l?l?l?s",
"?s?l?l?l?l",
"?s?l?l?l?l?l",
"?s?l?l?l?l?l?l",
"?s?l?l?l?l?l?l?l",
"?s?S?l?l?l?l",
"?u?d?d?d?d?d?d",
"?u?d?d?d?d?d?d?d?d",
"?u?l?d?d?d?d?d",
"?u?l?d?d?d?d?d?d",
"?u?l?d?d?d?d?d?d?d",
"?u?l?l?d?d?d?d",
"?u?l?l?d?d?d?d?d",
"?u?l?l?d?d?d?d?d?d",
"?u?l?l?l?l",
"?u?l?l?l?l?d",
"?u?l?l?l?l?d?d",
"?u?l?l?l?l?d?d?d",
"?u?l?l?l?l?d?d?d?d",
"?u?l?l?l?l?d?s",
"?u?l?l?l?l?l",
"?u?l?l?l?l?l?d",
"?u?l?l?l?l?l?d?d",
"?u?l?l?l?l?l?d?d?d",
"?u?l?l?l?l?l?d?d?d?d",
"?u?l?l?l?l?l?d?s",
"?u?l?l?l?l?l?l",
"?u?l?l?l?l?l?l?d",
"?u?l?l?l?l?l?l?d?d",
"?u?l?l?l?l?l?l?d?s",
"?u?l?l?l?l?l?l?s",
"?u?l?l?l?l?l?l?s?s",
"?u?l?l?l?l?l?s",
"?u?l?l?l?l?l?s?s",
"?u?l?l?l?l?s",
"?u?l?l?l?l?s?s"]

#Liste des règles possible fournit avec hashcat
rules = ["/usr/share/hashcat/rules/Incisive-leetspeak.rule",
"/usr/share/hashcat/rules/InsidePro-HashManager.rule",
"/usr/share/hashcat/rules/InsidePro-PasswordsPro.rule",
"/usr/share/hashcat/rules/T0XlC-insert_00-99_1950-2050_toprules_0_F.rule",
"/usr/share/hashcat/rules/T0XlC-insert_space_and_special_0_F.rule",
"/usr/share/hashcat/rules/T0XlC-insert_top_100_passwords_1_G.rule",
"/usr/share/hashcat/rules/T0XlC.rule",
"/usr/share/hashcat/rules/T0XlCv1.rule",
"/usr/share/hashcat/rules/best64.rule",
"/usr/share/hashcat/rules/combinator.rule",
"/usr/share/hashcat/rules/d3ad0ne.rule",
"/usr/share/hashcat/rules/dive.rule",
"/usr/share/hashcat/rules/generated.rule",
"/usr/share/hashcat/rules/generated2.rule",
"/usr/share/hashcat/rules/leetspeak.rule",
"/usr/share/hashcat/rules/oscommerce.rule",
"/usr/share/hashcat/rules/rockyou-30000.rule",
"/usr/share/hashcat/rules/specific.rule",
"/usr/share/hashcat/rules/toggles1.rule",
"/usr/share/hashcat/rules/toggles2.rule",
"/usr/share/hashcat/rules/toggles3.rule",
"/usr/share/hashcat/rules/toggles4.rule",
"/usr/share/hashcat/rules/toggles5.rule"]

# Demande les entrées utilisateurs
a = raw_input("Enter Attack Mode Number:")
b = raw_input("Enter a hash file:")
c = raw_input("Enter your wordlist file or Dir:")
d = raw_input("Enter the attack mode (0/1/2/3 - Straight/Combination/Toggle/Brute) : ")

#Commande de base
#call(["hashcat", "-m", a, "-a", d,"--remove", "--force", "-o", "results.txt", b, c])

#Enumération sur tout les masques
for mask in masks:
    call(["hashcat", "-m", a, "-a", "6", "--remove", "--force", "-o", "results.txt", b, c, mask])

#Enumération sur toute les règles
for rule in rules:
    call(["hashcat", "-m", a,"--remove", "--force", "-r", rule, "-o", "results.txt", b, c])
